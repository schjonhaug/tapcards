// package tapcards provides a simple queue implementation.
package tapcards

import "log/slog"

// queue is a basic FIFO queue based on a slice of interface{}.
type queue struct {
	elements []interface{}
}

// enqueue adds an element to the end of the queue.
// It logs the enqueued element using slog.Debug.
func (q *queue) enqueue(element interface{}) {
	slog.Debug("Enqueue", "Command", element)
	q.elements = append(q.elements, element)
}

// dequeue removes an element from the start of the queue.
// It returns nil if the queue is empty.
// It logs the dequeued element using slog.Debug.
func (q *queue) dequeue() interface{} {
	if len(q.elements) == 0 {
		return nil
	}

	element := q.elements[0]
	q.elements = q.elements[1:]

	slog.Debug("Dequeue", "Command", element)
	return element
}

// peek returns the first element of the queue without removing it.
// It returns nil if the queue is empty.
// It logs the peeked element using slog.Debug.
func (q *queue) peek() interface{} {
	if len(q.elements) == 0 {
		return nil
	}
	element := q.elements[0]
	slog.Debug("Peek", "Command", element)
	return element
}

// size returns the number of elements in the queue.
func (q *queue) size() int {
	return len(q.elements)
}
