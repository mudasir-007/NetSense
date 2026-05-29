#include "load_balancer.h"
#include <iostream>
#include <chrono>
#include <stdexcept>

/*
    load_balancer.cpp

    The LoadBalancer thread loop is intentionally very simple:
        1. Pop packet from input queue (blocks if empty)
        2. Hash the FiveTuple to pick a FP index
        3. Push packet to that FP's queue
        4. Update counters
        5. Repeat

    No flow state, no classification, no rules — just routing.
    All the interesting work happens in FastPath threads.
*/

namespace DPI
{
    /*
        LoadBalancer constructor

        input_queue_ is bounded to 10k packets.
        This provides natural backpressure:
            If FP threads cannot keep up,
            the LB queue eventually fills,
            slowing the reader thread automatically.
    */
    LoadBalancer::LoadBalancer(
        int lb_id,
        std::vector<ThreadSafeQueue<PacketJob> *> fp_queues,
        int fp_start_id)
        : lb_id_(lb_id),
          fp_start_id_(fp_start_id),
          num_fps_(static_cast<int>(fp_queues.size())),
          input_queue_(10000), // bounded at 10k packets
          fp_queues_(std::move(fp_queues)),
          per_fp_counts_(num_fps_, 0) // one counter per FP
    {
    }

    LoadBalancer::~LoadBalancer()
    {
        stop();
    }

    /*
        start()

        Launches the LB worker thread.

        Idempotent:
            Calling start() multiple times is safe.
            Only the first call actually creates the thread.
    */
    void LoadBalancer::start()
    {
        if (running_.load())
            return;

        running_.store(true);

        thread_ = std::thread(&LoadBalancer::run, this);

        std::cout << "[LB" << lb_id_ << "] Started"
                  << " (serving FP" << fp_start_id_
                  << "-FP" << (fp_start_id_ + num_fps_ - 1)
                  << ")\n";
    }

    /*
        stop()

        Signals the LB thread to exit and waits for it.

        Shutdown order matters:
            1. Set running_ = false
            2. Shutdown queue to wake blocked pop()
            3. Join thread

        Idempotent:
            Safe to call multiple times.
    */
    void LoadBalancer::stop()
    {
        if (!running_.load())
            return;

        running_.store(false);

        // Wake up the thread if blocked waiting for packets
        input_queue_.shutdown();

        if (thread_.joinable())
        {
            thread_.join();
        }

        std::cout << "[LB" << lb_id_ << "] Stopped"
                  << " (dispatched "
                  << packets_dispatched_.load()
                  << " packets)\n";
    }

    /*
        run()

        Main LB worker loop.

        Uses popWithTimeout() instead of a fully blocking pop()
        so the thread periodically wakes up and checks running_.

        This avoids shutdown deadlocks where the LB thread could
        otherwise sleep forever on an empty queue.

        100ms timeout means:
            worst-case shutdown latency ≈ 100ms

        which is perfectly acceptable for an offline analyzer.
    */
    void LoadBalancer::run()
    {
        while (running_.load())
        {
            // Wait up to 100ms for a packet
            auto job_opt =
                input_queue_.popWithTimeout(
                    std::chrono::milliseconds(100));

            /*
                popWithTimeout() returns std::nullopt if:
                    - timeout expires
                    - queue is shutdown

                In both cases we simply continue and re-check running_.
            */
            if (!job_opt)
                continue;

            packets_received_++;

            // Determine which FP should process this packet
            int fp_index = selectFP(job_opt->tuple);

            /*
                Push packet into the selected FP queue.

                NOTE:
                    push() may block if the FP queue is full.

                    In this offline analyzer design,
                    FP threads are expected to continue draining
                    their queues during shutdown.
            */
            fp_queues_[fp_index]->push(std::move(*job_opt));

            packets_dispatched_++;

            // Only this LB thread writes this vector → no atomics needed
            per_fp_counts_[fp_index]++;
        }
    }

    /*
        selectFP()

        Uses consistent hashing to pick which FP thread
        should process this packet.

        We reuse FiveTupleHash:
            hash(tuple) % num_fps_

        Because hashing is deterministic:
            same input → same output

        the same FiveTuple always maps to the same FP index.

        Combined with the reader's LB selection:
            same tuple → same LB → same FP

        giving globally stable flow affinity.
    */
    int LoadBalancer::selectFP(const FiveTuple &tuple) const
    {
        FiveTupleHash hasher;

        size_t hash_value = hasher(tuple);

        // Maps hash into range [0, num_fps_ - 1]
        return static_cast<int>(
            hash_value % static_cast<size_t>(num_fps_));
    }

    /*
        getStats()

        Returns statistics for this LB.

        packets_received_ and packets_dispatched_
        are atomic and safe to read anytime.

        per_fp_counts_ is non-atomic but only written
        by the LB thread itself.

        Reading it after processing completes is safe.
    */
    LoadBalancer::LBStats LoadBalancer::getStats() const
    {
        LBStats stats;

        stats.packets_received =
            packets_received_.load();

        stats.packets_dispatched =
            packets_dispatched_.load();

        // Copy vector into returned stats struct
        stats.per_fp_counts = per_fp_counts_;

        return stats;
    }

    /*
        LBManager constructor

        Creates all LoadBalancer objects.

        The flat fp_queues vector is sliced into
        per-LB subsets.

        Example:
            num_lbs = 2
            fps_per_lb = 2

            fp_queues = [Q0, Q1, Q2, Q3]

            LB0 gets:
                [Q0, Q1]

            LB1 gets:
                [Q2, Q3]
    */
    LBManager::LBManager(
        int num_lbs,
        int fps_per_lb,
        std::vector<ThreadSafeQueue<PacketJob> *> fp_queues)
        : fps_per_lb_(fps_per_lb)
    {
        for (int lb_id = 0; lb_id < num_lbs; lb_id++)
        {
            // Starting index inside the flat fp_queues vector
            int start_idx = lb_id * fps_per_lb;

            /*
                Global FP ID of this LB's first FP.

                Used only for logging/debugging.
            */
            int fp_start_id = start_idx;

            /*
                Build subset of FP queues belonging
                to this LB.
            */
            std::vector<ThreadSafeQueue<PacketJob> *> lb_fp_queues;

            for (int i = 0; i < fps_per_lb; i++)
            {
                lb_fp_queues.push_back(
                    fp_queues[start_idx + i]);
            }

            lbs_.push_back(
                std::make_unique<LoadBalancer>(
                    lb_id,
                    std::move(lb_fp_queues),
                    fp_start_id));
        }

        std::cout << "[LBManager] Created "
                  << num_lbs
                  << " load balancer(s), "
                  << fps_per_lb
                  << " FP(s) each\n";
    }

    LBManager::~LBManager()
    {
        stopAll();
    }

    /*
        startAll()

        Starts every LB thread.
    */
    void LBManager::startAll()
    {
        for (auto &lb : lbs_)
        {
            lb->start();
        }
    }

    /*
        stopAll()

        Stops every LB thread.
    */
    void LBManager::stopAll()
    {
        for (auto &lb : lbs_)
        {
            lb->stop();
        }
    }

    /*
        getLBForPacket()

        Called by the reader thread once per packet.

        Determines which LB should receive the packet.

        Uses:
            hash(tuple) % num_lbs

        Because the same FiveTuple always hashes
        identically, the same flow always reaches
        the same LB.

        Combined with selectFP():
            same tuple
                → same LB
                → same FP

        Global FP index formula:
            lb_index * fps_per_lb + fp_index_within_lb
    */
    LoadBalancer &LBManager::getLBForPacket(
        const FiveTuple &tuple)
    {
        if (lbs_.empty())
        {
            throw std::runtime_error(
                "LBManager has no load balancers");
        }

        FiveTupleHash hasher;

        size_t hash_value = hasher(tuple);

        int lb_index =
            static_cast<int>(
                hash_value % lbs_.size());

        return *lbs_[lb_index];
    }

    /*
        getAggregatedStats()

        Combines statistics across all LB threads.
    */
    LBManager::AggregatedStats
    LBManager::getAggregatedStats() const
    {
        AggregatedStats total{0, 0};

        for (const auto &lb : lbs_)
        {
            auto stats = lb->getStats();

            total.total_received +=
                stats.packets_received;

            total.total_dispatched +=
                stats.packets_dispatched;
        }

        return total;
    }

} // namespace DPI