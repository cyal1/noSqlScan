package burp;

//                     processProxyMessage                         processHttpMessage
//
//        client    ----------------------->    burpSuit proxy  ----------------------->    server
//                  <-----------------------                    <-----------------------

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

public class Custom implements IBurpExtender, IHttpListener, IProxyListener{
    private final String hostCondition = "www.baidu.com";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        this.helper = this.callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Event listeners");

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        String Host = messageInfo.getHttpService().getHost();

        if(!Host.equals(hostCondition)){
            return;
        }

        byte[] request = messageInfo.getRequest();
        byte[] response = messageInfo.getResponse();

        IRequestInfo reqInfo = helper.analyzeRequest(request);
        IResponseInfo respInfo = helper.analyzeResponse(response);


        if (messageIsRequest){
            // processHttpMessage request

            List<String> headers =  reqInfo.getHeaders();
            List<IParameter> parameters = reqInfo.getParameters();
            byte[] body = Arrays.copyOfRange(request,reqInfo.getBodyOffset(),request.length);

            headers.add("Test: test");
            parameters.add(helper.buildParameter("debug","true", IParameter.PARAM_URL));

            byte[] newMessage = helper.buildHttpMessage(headers, body);
            messageInfo.setRequest(newMessage);

        }else{
            // processHttpMessage response

            int statusCode = respInfo.getStatusCode();
            List<String> headers = respInfo.getHeaders();
            byte[] body = Arrays.copyOfRange(response, respInfo.getBodyOffset(), response.length);

            headers.add("Test: test");

            byte[] newMessage = helper.buildHttpMessage(headers, body);
            messageInfo.setResponse(newMessage);
        }

    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
        IHttpRequestResponse messageInfo = message.getMessageInfo();
        String Host = messageInfo.getHttpService().getHost();

        if(!Host.equals(hostCondition)){
            return;
        }

        byte[] request = messageInfo.getRequest();
        byte[] response = messageInfo.getResponse();

        IRequestInfo reqInfo = helper.analyzeRequest(request);
        IResponseInfo respInfo = helper.analyzeResponse(response);


        if (messageIsRequest){
            // processProxyMessage request

            List<String> headers =  reqInfo.getHeaders();
            List<IParameter> parameters = reqInfo.getParameters();
            byte[] body = Arrays.copyOfRange(request,reqInfo.getBodyOffset(),request.length);

            headers.add("Test: test");
            parameters.add(helper.buildParameter("debug","true", IParameter.PARAM_URL));

            byte[] newMessage = helper.buildHttpMessage(headers, body);
            messageInfo.setRequest(newMessage);

        }else{
            // processProxyMessage response

            int statusCode = respInfo.getStatusCode();
            List<String> headers = respInfo.getHeaders();
            byte[] body = Arrays.copyOfRange(response, respInfo.getBodyOffset(), response.length);

            headers.add("Test: test");

            byte[] newMessage = helper.buildHttpMessage(headers, body);
            messageInfo.setResponse(newMessage);
        }
    }
}














