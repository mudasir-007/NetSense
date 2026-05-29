#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "types.h"
#include "thread_safe_queue.h"

#include <thread>
#include <vector>
#include <atomic>
#include <memory>

/*
    load_balancer.h

    Two classes:

        LoadBalancer
            One thread that receives packets from the reader
            and distributes them to a pool of FP threads using
            consistent hashing on the FiveTuple.

        LBManager
            Creates and manages multiple LoadBalancer threads,
            and exposes getLBForPacket() so the reader can push
            directly to the correct LB queue.

    Consistent hashing guarantee:

        The same FiveTuple always produces the same hash value.

        hash(tuple) % fps_per_lb
            always selects the same FP index.

        Therefore the same connection always reaches
        the same FP thread.

        This guarantees the FP's flow table always contains
        the connection entry for subsequent packets,
        meaning we never lose classification state.
*/

namespace DPI
{
    /*
        =========================================================================
        LoadBalancer

        One LB thread serving a fixed subset of FP queues.
        =========================================================================
    */
    class LoadBalancer
    {
    public:
        /*
            lb_id:
                Which LB this is (0, 1, 2, ...)

                Used for logging/debugging.

            fp_queues:
                Raw pointers to the FP input queues this LB feeds.

                FP threads OWN these queues.
                The LB only pushes packets into them.

            fp_start_id:
                Global FP ID of fp_queues[0].

                Used only for readable logging output.
        */
        LoadBalancer(
            int lb_id,
            std::vector<ThreadSafeQueue<PacketJob> *> fp_queues,
            int fp_start_id);

        ~LoadBalancer();

        /*
            start()

            Launches the LB worker thread.

            The thread begins:
                - draining input_queue_
                - hashing packets
                - dispatching to FP queues
        */
        void start();

        /*
            stop()

            Signals the LB thread to exit,
            shuts down the input queue,
            and joins the worker thread.
        */
        void stop();

        /*
            getInputQueue()

            Reader thread pushes packets here.

            LB thread pops packets from this queue.
        */
        ThreadSafeQueue<PacketJob> &getInputQueue()
        {
            return input_queue_;
        }

        /*
            Per-LB statistics.
        */
        struct LBStats
        {
            // Number of packets popped from input_queue_
            uint64_t packets_received;

            // Number of packets successfully pushed to FP queues
            uint64_t packets_dispatched;

            /*
                Per-FP dispatch counts.

                Example:
                    per_fp_counts[0] = packets sent to FP0
                    per_fp_counts[1] = packets sent to FP1
            */
            std::vector<uint64_t> per_fp_counts;
        };

        // Snapshot current statistics
        LBStats getStats() const;

        // Accessors
        int getId() const
        {
            return lb_id_;
        }

        bool isRunning() const
        {
            return running_.load();
        }

    private:
        // Which LB this object represents
        int lb_id_;

        /*
            Global FP ID of our first FP queue.

            Example:
                LB0 serves FP0-FP1
                LB1 serves FP2-FP3

            Then:
                LB0.fp_start_id_ = 0
                LB1.fp_start_id_ = 2
        */
        int fp_start_id_;

        // Number of FP queues this LB serves
        int num_fps_;

        /*
            Reader thread pushes packets here.

            LB thread drains packets from here.
        */
        ThreadSafeQueue<PacketJob> input_queue_;

        /*
            Outbound FP queues.

            One queue per FP thread.

            Ownership:
                FP threads own the queues.
                LB only stores raw pointers.
        */
        std::vector<ThreadSafeQueue<PacketJob> *> fp_queues_;

        /*
            Per-FP dispatch counters.

            Non-atomic because:
                only this LB thread writes them.
        */
        std::vector<uint64_t> per_fp_counts_;

        /*
            Atomic counters because they may be read
            concurrently by a reporting/stats thread.
        */
        std::atomic<uint64_t> packets_received_{0};
        std::atomic<uint64_t> packets_dispatched_{0};

        /*
            Thread lifecycle control.
        */
        std::atomic<bool> running_{false};

        // Worker thread running run()
        std::thread thread_;

        /*
            run()

            Main LB worker loop.

            Continuously:
                1. Pop packet from input queue
                2. Hash FiveTuple
                3. Select FP queue
                4. Push packet to FP queue
        */
        void run();

        /*
            selectFP()

            Uses consistent hashing to select which FP
            should process this packet.

            Same FiveTuple
                → same hash
                → same FP index
        */
        int selectFP(const FiveTuple &tuple) const;
    };

    /*
        =========================================================================
        LBManager

        Creates and manages all LoadBalancer threads.
        =========================================================================
    */
    class LBManager
    {
    public:
        /*
            num_lbs:
                Number of LB threads to create.

            fps_per_lb:
                Number of FP threads each LB serves.

            fp_queues:
                Flat vector containing ALL FP queues.

                LBManager slices this vector into
                per-LB subsets.

            Example:

                num_lbs = 2
                fps_per_lb = 2

                fp_queues:
                    [Q0, Q1, Q2, Q3]

                LB0 receives:
                    [Q0, Q1]

                LB1 receives:
                    [Q2, Q3]
        */
        LBManager(
            int num_lbs,
            int fps_per_lb,
            std::vector<ThreadSafeQueue<PacketJob> *> fp_queues);

        ~LBManager();

        // Start all LB threads
        void startAll();

        // Stop all LB threads
        void stopAll();

        /*
            getLBForPacket()

            Reader thread calls this once per packet.

            Uses:
                hash(tuple) % num_lbs

            to determine which LB should receive
            the packet.

            Same FiveTuple
                → same LB
                → same FP
        */
        LoadBalancer &getLBForPacket(const FiveTuple &tuple);

        // Direct indexed access
        LoadBalancer &getLB(int id)
        {
            return *lbs_[id];
        }

        // Number of LB threads
        int getNumLBs() const
        {
            return static_cast<int>(lbs_.size());
        }

        /*
            Aggregated statistics across all LBs.
        */
        struct AggregatedStats
        {
            uint64_t total_received;
            uint64_t total_dispatched;
        };

        // Sum stats from all LB threads
        AggregatedStats getAggregatedStats() const;

    private:
        // All LoadBalancer objects
        std::vector<std::unique_ptr<LoadBalancer>> lbs_;

        // Number of FP threads each LB owns
        int fps_per_lb_;
    };

} // namespace DPI

#endif // LOAD_BALANCER_H