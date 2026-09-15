package packet_analyzer;

import java.util.*;

public final class Queue<T> {
    private final ArrayDeque<T> q = new ArrayDeque<>();
    private final int max;
    private boolean shutdown = false;

    public Queue() {
        this(10000);
    }

    public Queue(int m) {
        max = m;
    }

    public synchronized void push(T item) {
        try {
            while (q.size() >= max && !shutdown) wait();
            if (shutdown) return;
            q.add(item);
            notifyAll();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public synchronized Optional<T> pop(long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        try {
            while (q.isEmpty() && !shutdown) {
                long r = end - System.currentTimeMillis();
                if (r <= 0) return Optional.empty();
                wait(r);
            }
            if (q.isEmpty()) return Optional.empty();
            T x = q.remove();
            notifyAll();
            return Optional.of(x);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    public synchronized void shutdown() {
        shutdown = true;
        notifyAll();
    }

    public synchronized int size() {
        return q.size();
    }

    public synchronized boolean isShutdown() {
        return shutdown;
    }
}
