package tapcards

import "log/slog"

type queue struct {
	elements []interface{}
}

func (q *queue) enqueue(element interface{}) {
	slog.Debug("Enqueue", "Command", element)
	q.elements = append(q.elements, element)
}

func (q *queue) dequeue() interface{} {
	if len(q.elements) == 0 {
		return nil
	}

	element := q.elements[0]
	q.elements = q.elements[1:]

	slog.Debug("Dequeue", "Command", element)
	return element
}

func (q *queue) peek() interface{} {
	if len(q.elements) == 0 {
		return nil
	}
	element := q.elements[0]
	slog.Debug("Peek", "Command", element)
	return element
}
func (q *queue) size() int {
	return len(q.elements)
}

func (q *queue) isEmpty() bool {
	return len(q.elements) == 0
}
