package org.pvv.rolfn.tls;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.*;
import java.util.Map.Entry;

import javax.net.ssl.SSLContext;

import org.apache.commons.lang3.text.WordUtils;
import org.apache.log4j.Logger;
import org.kohsuke.args4j.*;



/**
 * Hello world!
 *
 */
public class TLSTest 
{
	private static final String LINE = "---------------------------------------------------------------------------------";

	private final static Logger log = Logger.getLogger(TLSTest.class.getName());
	
	@Option(name="-provider", usage="select cryptography provider")
	private String provider = null;
	
	@Option(name="-service", usage="list info on given service, provider must be given")
	private String service = null;
	
	@Option(name="-providercfg", usage="properties loadable from classpath to find more providers")
	private String providercfg = null;
	
	@Option(name="-onlyssl", usage="only list SSLContext-services")
	private boolean onlyssl = false;
	
	@Argument
	private List<String> arguments = new ArrayList<String>();
	
    public TLSTest(String[] args) {
    	CmdLineParser parser = new CmdLineParser(this);
    	try {
			parser.parseArgument(args);
			if(service != null && provider == null) {
				throw new CmdLineException(parser, "provider must be specified to select service");
			}
		} catch (CmdLineException e) {
			System.err.println("java "+this.getClass().getCanonicalName()+" arguments...");
			parser.printUsage(System.err);
			System.err.println();
			throw new RuntimeException(e);
		}
	}

    private static void loadProvider(String providerClassName) {
    	try {
			Security.addProvider((Provider) Class.forName(providerClassName).newInstance());
		} catch (Exception e) {
			log.warn("error loading security provider "+providerClassName);
		}
    }
    
	public static void main( String[] args )
    {
    	try {
			TLSTest main = new TLSTest(args);
			if(main.providercfg != null) {
				try {
					InputStream propertiesStream = TLSTest.class.getClassLoader().getResourceAsStream(main.providercfg);
					Properties providers = new Properties();
					providers.load(propertiesStream);
					for(Entry<Object, Object> e: providers.entrySet()) {
						if(((String)e.getKey()).startsWith("provider.")) {
							loadProvider((String)e.getValue());
						}
					}
				} catch (IOException e) {
					log.error("Unable to load providers from "+main.providercfg+": "+e.getMessage());
				}				
			}
			
			if(main.service == null) {
				main.listProviders();
			} else {
				main.listService();
			}
		} catch (RuntimeException e) {
			System.err.println(e.getMessage());
		} 
    	
    }

	public void listService() {
		Provider p = Security.getProvider(provider);
		for(Service s: p.getServices()) {
			if(service.equals(s.getAlgorithm())) {
				printService(s);
			}
		}
	}

	private void printService(Service s) {
		if("SSLContext".equals(s.getType())) {
			try {
				Collection<String> orderedCipherList = new TreeSet<String>();
				System.out.println(s.getProvider().getName()+": "+s.getType()+" "+s.getAlgorithm());
				SSLContext ctx = SSLContext.getInstance(s.getAlgorithm(), s.getProvider());
				ctx.init(null, null, null);
				for(String cipher: ctx.getSupportedSSLParameters().getCipherSuites()) {
					orderedCipherList.add(cipher);
				}
				for(String cipher: orderedCipherList) {
					System.out.println(cipher);
				}
			} catch (NoSuchAlgorithmException e) {
				log.warn(e.toString());
			} catch (KeyManagementException e) {
				log.warn(e.toString());
			}
		}
	}

	public void listProviders() {
		if(provider != null) {
			printProvider(Security.getProvider(provider));
		} else {
			System.out.println(String.format("%-10s %s", "Provider", "Description"));
			System.out.println(String.format("%10.10s %69.69s", LINE, LINE));
			for(Provider p: Security.getProviders()) {
				System.out.println(String.format("%-10s %s", p.getName(), WordUtils.wrap(p.getInfo(), 69, "\n           ", true)));
				System.out.println();
			}
		}
	}

	private void printProvider(Provider p) {
		System.out.println("Provider: "+p.getName());
		System.out.println("Info    : "+p.getInfo());
		System.out.println("Services: ");
		for(Service s: p.getServices()) {
			if(!onlyssl || "SSLContext".equals(s.getType())) {
				System.out.println(" - "+s.getType()+": "+s.getAlgorithm());
			}
		}
	}
}
