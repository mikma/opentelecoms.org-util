/*
 *  Encapsulates all the logic required to obtain and parse DNS SRV
 *  records and provide the corresponding InetAddresses as an
 *  ordered Collection (the class itself extends Vector)
 *  
 *  If SRV records don't exist for a particular domain/service,
 *  then any A records for the domain will be obtained instead
 *  (maybe this should be extended to CNAME records)
 *  
 *  Copyright 2012 Daniel Pocock <daniel@pocock.com.au>
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.opentelecoms.util.dns;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;


public class SRVRecordHelper extends Vector<InetSocketAddress> {

	public interface Service {
		String getName();
		int getDefaultPort();
		String getDefaultProtocol();
	}

	Logger logger = Logger.getLogger(getClass().getName());
	
	private static final long serialVersionUID = -2656070797887094655L;
	final private String TAG = "SRVRecordHelper";
	private String useProtocol;

	public String getProtocol() { return useProtocol; }

	private class RecordHelperThread extends Thread {
		
		CyclicBarrier barrier;
		String domain;
		int type;
		Vector<Record> records;
		public RecordHelperThread(CyclicBarrier barrier, String domain, int type) {
			this.barrier = barrier;
			this.domain = domain;
			this.type = type;
		}
				
		public Collection<Record> getRecords() {
			return records;
		}

		public void run() {
			try {
				
				try {
					Resolver resolver = new ExtendedResolver();
					resolver.setTimeout(2);
					Lookup lookup = new Lookup(domain, type);
					lookup.setResolver(resolver);
					records = new Vector<Record>();
					Record[] _records = null;
				
					try {
						_records = lookup.run();
					} catch (Exception ex) {
						// ignore the exception, as we try the lookup
						// in different ways
						logger.log(Level.SEVERE, "exception", ex);
					}
				
					if (_records != null)
						for(Record record : _records)
							records.add(record);
				} catch (Exception ex) {
					records = null;
				}
				barrier.await();
			} catch (InterruptedException ex) {
				ex.printStackTrace();
			} catch (BrokenBarrierException ex) {
				ex.printStackTrace();
			}
		}
	}
	
	public SRVRecordHelper(Service service, String protocol, String domain, int port) {
		boolean withProtocol = protocol.length() > 0;
		boolean withPort = port > 0;
		boolean withNumeric;
		byte[] rawV4 = null;
		byte[] rawV6 = null;

		rawV4 = IPAddressUtil.textToNumericFormatV4(domain);
		if ( rawV4 == null )
			rawV6 = IPAddressUtil.textToNumericFormatV6(domain);

		withNumeric = rawV4 != null || rawV6 != null;

		TreeSet<SRVRecord> srvRecords = new TreeSet<SRVRecord>(new SRVRecordComparator());
		Vector<ARecord> aRecords = new Vector<ARecord>();

		if ( withProtocol ) {
			useProtocol = protocol;
		} else {
			if ( withNumeric || withPort) {
				useProtocol = service.getDefaultProtocol();
			} else {
				// TODO try NAPTR
				// When no NAPTR found try SRV
				// Only SRV for now
				useProtocol = service.getDefaultProtocol();
			}
		}

		if ( withNumeric ) {
			int usePort = service.getDefaultPort();

			if ( withPort )
				usePort = port;
			else
				usePort = service.getDefaultPort();

			add(new InetSocketAddress(domain,
						  usePort));
			// No DNS lookup needed
			return;
		}

		try {
			int numQueries;
			if ( withPort )
				numQueries = 1; // A
			else
				numQueries = 2; // SRV + A

			CyclicBarrier b = new CyclicBarrier(numQueries + 1);
			RecordHelperThread srv_t = null;
			RecordHelperThread a_t = new RecordHelperThread(b, domain, Type.A);

			if ( !withPort ) {
				String mDomain = "_" + service.getName() + "._" + useProtocol + "." + domain;
				srv_t = new RecordHelperThread(b, mDomain, Type.SRV);
				srv_t.start();
			}

			a_t.start();
			
			// Wait for all lookups to finish
			try {
				b.await();
			} catch (InterruptedException e) {
				logger.log(Level.SEVERE, "InterruptedException", e);
			} catch (BrokenBarrierException e) {
				logger.log(Level.SEVERE, "BrokenBarrierException", e);
			}

			if ( srv_t != null ) {
				for (Record record : srv_t.getRecords()) {
					if(record instanceof SRVRecord) {
						srvRecords.add((SRVRecord)record);
					}
					if(record instanceof ARecord) {
						// In case of additional records
						aRecords.add((ARecord)record);
					}
				}
			}
			for (Record record : a_t.getRecords()) {
				if(record instanceof ARecord) {
					aRecords.add((ARecord)record);
				}
			}
		} catch (Exception ex) {
			logger.warning("Exception during DNS lookup: " + ex.getClass().getName() + ", " + ex.getMessage());
		}

		boolean srvFound = false;
		if ( srvRecords.size() > 0 ) {
			// Process SRV records
			for(SRVRecord srvRecord : srvRecords) {
				Name target = srvRecord.getTarget();
				int usePort = srvRecord.getPort();
				boolean addrFound = false;

				// Check A records first
				for(ARecord aRecord : aRecords) {
					if ( aRecord.getName() == target ) {
						add(new InetSocketAddress(aRecord.getAddress(), usePort));
						addrFound = true;
						break;
					}
				}

				if ( addrFound )
					continue;
				// Lookup addresses
				try {
					InetAddress addr = InetAddress.getByName(target.toString());
					add(new InetSocketAddress(addr, usePort));
				} catch (UnknownHostException e) {
				}
			}
		}

		if( size() == 0 ) {
			// SRV not used or not found
			// Fallback to using A records
			int usePort = service.getDefaultPort();

			if ( withPort )
				usePort = port;
			else
				usePort = service.getDefaultPort();
			for(ARecord record : aRecords) {
				add(new InetSocketAddress(record.getAddress(), usePort));
			}
		}
	}
}
