package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender{
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helper;
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        BurpExtender.callbacks = callbacks;
        helper = BurpExtender.callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("noSqlScan");

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        NoSqlScan nss =  new NoSqlScan();
        callbacks.registerContextMenuFactory(nss);

    }
}












