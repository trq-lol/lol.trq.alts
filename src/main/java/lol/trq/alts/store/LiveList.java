package lol.trq.alts.store;

import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;
import java.util.Spliterator;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.IntFunction;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

/**
 * The list {@link AccountStore#accounts()} hands out: copy-on-write like the
 * {@link CopyOnWriteArrayList} it wraps, so a reader iterates a snapshot while another thread mutates,
 * with one addition, {@link #replaceContents}, which swaps the whole contents in one step. A load uses
 * it, so a reader on another thread never sees the list empty, or half-filled, between the old
 * contents and the new.
 *
 * <p>Every operation reads the current backing list once and runs on it, so each is as atomic as the
 * same operation on a {@code CopyOnWriteArrayList}. A mutation racing a swap lands on the list the swap
 * replaced and is lost with it, exactly as it would be overwritten by the load it raced; the store's own
 * mutators and its load run under one lock and never race.
 *
 * @param <E> the element type
 * @author trq
 * @since 1.0.0
 */
final class LiveList<E> implements List<E>, RandomAccess {

    private volatile CopyOnWriteArrayList<E> current = new CopyOnWriteArrayList<>();

    /**
     * Replaces the whole contents with {@code contents}, in one step as far as any reader is concerned.
     *
     * @param contents the new contents, copied
     */
    void replaceContents(Collection<? extends E> contents) {
        current = new CopyOnWriteArrayList<>(contents);
    }

    @Override
    public int size() {
        return current.size();
    }

    @Override
    public boolean isEmpty() {
        return current.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return current.contains(o);
    }

    @Override
    public Iterator<E> iterator() {
        return current.iterator();
    }

    @Override
    public Object[] toArray() {
        return current.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return current.toArray(a);
    }

    @Override
    public <T> T[] toArray(IntFunction<T[]> generator) {
        return current.toArray(generator);
    }

    @Override
    public boolean add(E e) {
        return current.add(e);
    }

    @Override
    public boolean remove(Object o) {
        return current.remove(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return current.containsAll(c);
    }

    @Override
    public boolean addAll(Collection<? extends E> c) {
        return current.addAll(c);
    }

    @Override
    public boolean addAll(int index, Collection<? extends E> c) {
        return current.addAll(index, c);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return current.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return current.retainAll(c);
    }

    @Override
    public boolean removeIf(Predicate<? super E> filter) {
        return current.removeIf(filter);
    }

    @Override
    public void replaceAll(UnaryOperator<E> operator) {
        current.replaceAll(operator);
    }

    @Override
    public void sort(Comparator<? super E> c) {
        current.sort(c);
    }

    @Override
    public void clear() {
        current.clear();
    }

    @Override
    public E get(int index) {
        return current.get(index);
    }

    @Override
    public E set(int index, E element) {
        return current.set(index, element);
    }

    @Override
    public void add(int index, E element) {
        current.add(index, element);
    }

    @Override
    public E remove(int index) {
        return current.remove(index);
    }

    @Override
    public int indexOf(Object o) {
        return current.indexOf(o);
    }

    @Override
    public int lastIndexOf(Object o) {
        return current.lastIndexOf(o);
    }

    @Override
    public ListIterator<E> listIterator() {
        return current.listIterator();
    }

    @Override
    public ListIterator<E> listIterator(int index) {
        return current.listIterator(index);
    }

    @Override
    public List<E> subList(int fromIndex, int toIndex) {
        return current.subList(fromIndex, toIndex);
    }

    @Override
    public Spliterator<E> spliterator() {
        return current.spliterator();
    }

    @Override
    public Stream<E> stream() {
        return current.stream();
    }

    @Override
    public Stream<E> parallelStream() {
        return current.parallelStream();
    }

    @Override
    public void forEach(Consumer<? super E> action) {
        current.forEach(action);
    }

    @Override
    public void addFirst(E e) {
        current.addFirst(e);
    }

    @Override
    public void addLast(E e) {
        current.addLast(e);
    }

    @Override
    public E getFirst() {
        return current.getFirst();
    }

    @Override
    public E getLast() {
        return current.getLast();
    }

    @Override
    public E removeFirst() {
        return current.removeFirst();
    }

    @Override
    public E removeLast() {
        return current.removeLast();
    }

    @Override
    public List<E> reversed() {
        return current.reversed();
    }

    @Override
    public boolean equals(Object o) {
        return o == this || current.equals(o);
    }

    @Override
    public int hashCode() {
        return current.hashCode();
    }

    @Override
    public String toString() {
        return current.toString();
    }
}
