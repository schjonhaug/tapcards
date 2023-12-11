package tapcards

import "log/slog"

type queue struct {
	elements []interface{}
}

func (q *queue) Enqueue(element interface{}) {
	slog.Debug("Enqueue", "Command", element)
	q.elements = append(q.elements, element)
}

func (q *queue) Dequeue() interface{} {
	if len(q.elements) == 0 {
		return nil
	}

	element := q.elements[0]
	q.elements = q.elements[1:]

	slog.Debug("Dequeue", "Command", element)
	return element
}

func (q *queue) Peek() interface{} {
	if len(q.elements) == 0 {
		return nil
	}
	element := q.elements[0]
	slog.Debug("Peek", "Command", element)
	return element
}
func (q *queue) Size() int {
	return len(q.elements)
}

func (q *queue) IsEmpty() bool {
	return len(q.elements) == 0
}
