/*
    Lets make a multi-threaded version of this engine using threads.

    The single threaded version processes one packet at a time.

    In the multi-threaded version, multiple stages execute concurrently.
*/

// Intuition - the pipe between threads

/*
    we need a queue where:
        Producer (reader/LB thread) can push items in
        Consumer (LB/FP thread) can pop items out
        Both can happen simultaneously without corruption
        Consumer waits efficiently when queue is empty (no busy loop)
        Producer waits when queue is full (backpressure)
*/

#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>
#include <cstddef>

/*
    thread_safe_queue.h

    a bounded, thread safe FIFO queue used to pass PacketJob objects between the pipeline stages:

        Reader -> LS queue -> LB thread -> FP queue -> FP thread -> Output queue -> Writer

    Key design decisions:
        Bounded size (max_size):
            Prevents unbounded memory growth if a downstream thread falls
            behind. When full, push() blocks unntil space is available.
            This is called "backpressure" - fast producers slow down automatically to match slow consumers.

        Condition variables (not spin-wait):
            Threads sleep when waiting -  zero CPU usage while idle.
            A spinning thread would waste an entire core doing nothing.

        shutdown() flag:
            When we want to stop all threads clearly, we call shutdown()
            which wakes up all waiting threads so they can exit their loops.
            Without this, threads would block forever on empty queues.

        std::optional<> return from pop:
            Returns nullopt when shutdown or timeout - earlier can
            distinguish "got item" from "queue is done".
*/

namespace DPI
{
    template <typename T>

    class ThreadSafeQueue
    {
    public:
        // max_size: maximum number of items in queue before push() blcoks
        explicit ThreadSafeQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}

        // Destructor: ensure shutdown is signalled se no thread blcoks forver
        ~ThreadSafeQueue()
        {
            shutdown();
        }

        /*
            push() - add an item to the back odf the queue

            Blocks if the queue is full (backpressure).
            Returns immediately if shutdown has been called.

            Uses std::move to avoid copying large PacketJob objects.
        */
        void push(T item)
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // Wait until there is space OR we are shutting down
            // The lambda is the "wake up condition" — re-checked after each wakeup
            not_full_.wait(lock, [this]
                           { return queue_.size() < max_size_ || shutdown_; });

            // If we woke up due to shutdown, don't add the item
            if (shutdown_)
                return;

            queue_.push(std::move(item));

            // Signal one waiting consumer that an item is available
            not_empty_.notify_one();
        }

        /*
            tryPush() - non-blocking push

            returns true if item was added, false if queue is full or shutdown.

            Used when the caller has a feedback plan (e.g. try another queue)
        */
        bool tryPush(T item)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (queue_.size() >= max_size_ || shutdown_)
            {
                return false;
            }

            queue_.push(std::move(item));
            not_empty_.notify_one();
            return true;
        }

        /*
            pop() - remove and return the front item.

            Blocks indefinitely until an item is available or shutdown called.

            Returns std::nullopt on shutdown with empty queue.
        */
        std::optional<T> pop()
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // Wait until there is an item OR we are shutting down
            not_empty_.wait(lock, [this]
                            { return !queue_.empty() || shutdown_; });

            // Woke up but queue is still empty → must be shutdown
            if (queue_.empty())
                return std::nullopt;

            // Take the front item
            T item = std::move(queue_.front());
            queue_.pop();

            // Signal one waiting producer that space is now available
            not_full_.notify_one();

            return item;
        }

        /*
            popWithTimeout() - pop with a maximum wait time

            This is what FP and LP threads use in their loops.
            By timing out periodically, threads can check their running_. flaag.
            and exit cleanlu when stop()  is called.

            Returns atd::nullopt on timeout or shutdown.

            Example usage in a thread loop:

                while (running) {
                    auto item = queue.popWithTimeout(100nd);
                    if(!item) continue; // timeout - check running_ and loop
                    process(*item);
                }
        */
        std::optional<T> popWithTimeout(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // wait_for returns false if it timed out (condition still false)
            bool got_item = not_empty_.wait_for(lock, timeout, [this]
                                                { return !queue_.empty() || shutdown_; });

            // Timed out, or woke up due to shutdown with empty queue
            if (!got_item || queue_.empty())
            {
                return std::nullopt;
            }

            T item = std::move(queue_.front());
            queue_.pop();
            not_full_.notify_one();
            return item;
        }

        /*
            shutdown() - signal all waiting threads to wake up and exit.

            Called whrn the engine is stopping. After this:
                - push() returns without adding items.
                - pop() returns nullopt if queue becomes empty
                - popWithTimeout() returns nullopt immediately 

            Safe to call multiple times.
        */
        void shutdown()
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                shutdown_ = true;
            }
            // Wake up ALL waiting threads (not just one)
            not_empty_.notify_all();
            not_full_.notify_all();
        }

        // Utility queries - all acquire the lock for thread-safe reads
        bool empty() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return queue_.empty();
        }

        size_t size() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return queue_.size();
        }

        bool isShutdown() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return shutdown_;
        }

    private:
        std::queue<T> queue_;               // the actual storage
        mutable std::mutex mutex_;          // protects all access to queue_
        std::condition_variable not_empty_; // signalled when item added
        std::condition_variable not_full_;  // signalled when item removed
        size_t max_size_;                   // maximum items before blocking
        bool shutdown_;                     // true when engine is stopping
    };
}

#endif