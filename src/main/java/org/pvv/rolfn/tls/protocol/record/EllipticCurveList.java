package org.pvv.rolfn.tls.protocol.record;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

import org.pvv.rolfn.io.ByteBufferUtils;

public class EllipticCurveList implements List<NamedCurve>{
	private List<NamedCurve> ellipticCurveList;
	
	private EllipticCurveList(ByteBuffer buf) {
		int len = ByteBufferUtils.getUnsignedShort(buf);
		int start = buf.position();
		ellipticCurveList = new ArrayList<NamedCurve>();
		while(start+len > buf.position()) {
			ellipticCurveList.add(NamedCurve.read(buf));
		}
	}
	
	static protected EllipticCurveList read(ByteBuffer buf) {
		return new EllipticCurveList(buf);
	}
	
	// delegate methods
	
	public int size() {
		return ellipticCurveList.size();
	}
	
	public boolean isEmpty() {
		return ellipticCurveList.isEmpty();
	}
	
	public boolean contains(Object o) {
		return ellipticCurveList.contains(o);
	}
	
	public Iterator<NamedCurve> iterator() {
		return ellipticCurveList.iterator();
	}
	
	public Object[] toArray() {
		return ellipticCurveList.toArray();
	}
	
	public <T> T[] toArray(T[] a) {
		return ellipticCurveList.toArray(a);
	}
	
	public boolean add(NamedCurve e) {
		return ellipticCurveList.add(e);
	}
	
	public boolean remove(Object o) {
		return ellipticCurveList.remove(o);
	}
	
	public boolean containsAll(Collection<?> c) {
		return ellipticCurveList.containsAll(c);
	}
	
	public boolean addAll(Collection<? extends NamedCurve> c) {
		return ellipticCurveList.addAll(c);
	}
	
	public boolean addAll(int index, Collection<? extends NamedCurve> c) {
		return ellipticCurveList.addAll(index, c);
	}
	
	public boolean removeAll(Collection<?> c) {
		return ellipticCurveList.removeAll(c);
	}
	
	public boolean retainAll(Collection<?> c) {
		return ellipticCurveList.retainAll(c);
	}
	
	public void clear() {
		ellipticCurveList.clear();
	}
	
	public boolean equals(Object o) {
		return ellipticCurveList.equals(o);
	}
	
	public int hashCode() {
		return ellipticCurveList.hashCode();
	}
	
	public NamedCurve get(int index) {
		return ellipticCurveList.get(index);
	}
	
	public NamedCurve set(int index, NamedCurve element) {
		return ellipticCurveList.set(index, element);
	}
	
	public void add(int index, NamedCurve element) {
		ellipticCurveList.add(index, element);
	}
	
	public NamedCurve remove(int index) {
		return ellipticCurveList.remove(index);
	}
	
	public int indexOf(Object o) {
		return ellipticCurveList.indexOf(o);
	}
	
	public int lastIndexOf(Object o) {
		return ellipticCurveList.lastIndexOf(o);
	}
	
	public ListIterator<NamedCurve> listIterator() {
		return ellipticCurveList.listIterator();
	}
	
	public ListIterator<NamedCurve> listIterator(int index) {
		return ellipticCurveList.listIterator(index);
	}
	
	public List<NamedCurve> subList(int fromIndex, int toIndex) {
		return ellipticCurveList.subList(fromIndex, toIndex);
	}
}
