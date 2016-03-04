import java.io.File;

import space.davidboles.lib.ht.tp.FolderHttpHandler;
import space.davidboles.lib.ht.tp.HTTPSServerSimpleManager;
import space.davidboles.lib.program.ProgramFs;

public class Start {
	public static void main(String[] args) {
		try {
			File cert = ProgramFs.getProgramFile("cert/hrinc.davidboles.space.p12");
			HTTPSServerSimpleManager server = new HTTPSServerSimpleManager(871, cert, CertPassword.password);
			server.addHandler(new FolderHttpHandler("/", ProgramFs.getProgramFile("web")));
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	/*public static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
        	System.out.println("Handling");
            String response = "This is the response";
            HttpsExchange httpsExchange = (HttpsExchange) t;
            t.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }*/

    /**
     * @param args
     */
    /*public static void main(String[] args) throws Exception {

        try {
            // setup the socket address
            InetSocketAddress address = new InetSocketAddress(871);

            // initialise the HTTPS server
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // initialise the keystore
            char[] password = "4762DEB4762".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream("testkey.jks");
            ks.load(fis, password);

            // setup the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            // setup the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            // setup the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            
            FileInputStream fis = new FileInputStream(ProgramFs.getProgramFile("cert/hrinc.davidboles.space.p12"));
            //byte[] in = new byte[fis.available()];
            //fis.read(in);
            //String pkcs12Base64 = Base64.getEncoder().encodeToString(in);
            //while (fis.available()>0) pkcs12Base64 += String.
            
            
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, "4762DEB4762".toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "4762DEB4762".toCharArray());
            sslContext.init(kmf.getKeyManagers(), null, null);
            
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        // initialise the SSL context
                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        // get the default parameters
                        SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                        params.setSSLParameters(defaultSSLParameters);

                    } catch (Exception ex) {
                        System.out.println("Failed to create HTTPS port");
                    }
                }
            });
            httpsServer.createContext("/", new MyHandler());
            httpsServer.setExecutor(null); // creates a default executor
            httpsServer.start();

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 871 + " of localhost");
            exception.printStackTrace();

        }
    }*/
}
