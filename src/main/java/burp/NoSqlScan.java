package burp;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.*;
import com.fasterxml.jackson.databind.*;

import javax.swing.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class NoSqlScan implements IContextMenuFactory{

    private static final byte[] NOSQL_INJECTION = "$557c56fe3".getBytes();
    private static final byte[] MONGO_ERROR = "MongoError".getBytes();

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menuList = new ArrayList<>();
        if (invocation != null && invocation.getSelectedMessages() != null && invocation.getSelectedMessages()[0] != null && invocation.getSelectedMessages()[0].getHttpService() != null) {
            JMenuItem noSqlScan = new JMenuItem("noSqlScan");
            noSqlScan.addActionListener(e -> {
                    for (IHttpRequestResponse httpInfo:
                            invocation.getSelectedMessages()) {
                        byte[] reqBin = httpInfo.getRequest();
                        IRequestInfo requestInfo =  BurpExtender.helper.analyzeRequest(reqBin);
                        // content-size & method &  empty parameters filter
                        if ((requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART && reqBin.length > 40960) ||
                                Objects.equals(requestInfo.getMethod(), "OPTIONS") ||
                                requestInfo.getParameters().isEmpty()){
                            continue;
                        }
                        // mime filter
                        String mine = BurpExtender.helper.analyzeResponse(httpInfo.getResponse()).getStatedMimeType();
//                        BurpExtender.stdout.println(mine);
                        List<String> mineFilter = new ArrayList<>();
                        mineFilter.add("video");
                        mineFilter.add("PNG");
                        mineFilter.add("GIF");
                        if (mineFilter.contains(mine)){
                            continue;
                        }

                        if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_NONE ||
                                requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED||
                                requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART ||
                                requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON
                        ){
                                new Thread(() -> doScan(httpInfo)).start();
                        }
                    }
            });
            menuList.add(noSqlScan);
        }
        return menuList;
    }


    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<>();

        int start = 0;
        while (start < response.length)
        {
            start = BurpExtender.helper.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }


    public void doScan(IHttpRequestResponse baseRequestResponse)  {
        List<byte[]> newReqBinArr = new ArrayList<>();
        byte[] reqBin = baseRequestResponse.getRequest();
        IRequestInfo requestInfo =  BurpExtender.helper.analyzeRequest(baseRequestResponse.getHttpService(), reqBin);

        // json parameters
        if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
            int bodyOffset = requestInfo.getBodyOffset();
            String body = new String(reqBin, bodyOffset, reqBin.length - bodyOffset, StandardCharsets.UTF_8);
            ObjectMapper jackson = new ObjectMapper();
            JsonNode node;
            try {
                node = jackson.readTree(body);
            } catch (JsonProcessingException e) {
                BurpExtender.stderr.println(e.getMessage());
                throw new RuntimeException(e);
            }
            for (JsonNode j :
                    jsonIterator(node)) {
                byte[] newReqBin = BurpExtender.helper.buildHttpMessage(requestInfo.getHeaders(), BurpExtender.helper.stringToBytes(j.toString()));
                newReqBinArr.add(newReqBin);

            }
        }

        // queryString format parameters
        for  (IParameter param:
                requestInfo.getParameters()) {

            // skip _name parameter
            if(param.getName().startsWith("_")){
                continue;
            }
            if (param.getType() == IParameter.PARAM_URL || param.getType() == IParameter.PARAM_BODY){
                IParameter newParam = BurpExtender.helper.buildParameter(param.getName()+"%5B%24557c56fe3%5D", param.getValue(), param.getType());
                byte[] newReqBin = BurpExtender.helper.removeParameter(reqBin, param);
                newReqBin  = BurpExtender.helper.addParameter(newReqBin, newParam);
                newReqBinArr.add(newReqBin);
            };
        }

        for (byte[] newReqBin :
                newReqBinArr) {
            IHttpRequestResponse checkRequestResponse = BurpExtender.callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), newReqBin);

            byte[] respBin = checkRequestResponse.getResponse();

            checkRequestResponse.setHighlight("red"); //not work
            checkRequestResponse.setComment("noSqlScan"); //not work
//            BurpExtender.stdout.println(BurpExtender.helper.analyzeRequest(baseRequestResponse).getUrl()
//                    + "\t" + String.valueOf(BurpExtender.helper.analyzeResponse(respBin).getStatusCode()));

            List<int[]> matches = getMatches(respBin, NOSQL_INJECTION);
            List<int[]> matches2 = getMatches(respBin, MONGO_ERROR);

            if (matches.size() > 0)
            {
                if (matches2.size() > 0){
                    BurpExtender.callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            BurpExtender.helper.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[] { BurpExtender.callbacks.applyMarkers(checkRequestResponse, null, matches2) },
                            "NoSQL injection",
                            "Returned the string: " + BurpExtender.helper.bytesToString(MONGO_ERROR),
                            "High"));
                }else{
                    BurpExtender.callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            BurpExtender.helper.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[] { BurpExtender.callbacks.applyMarkers(checkRequestResponse, null, matches) },
                            "NoSQL injection possible",
                            "Returned the string: " + BurpExtender.helper.bytesToString(NOSQL_INJECTION),
                            "Medium"));
                }
            }
        }
        BurpExtender.stdout.println(requestInfo.getUrl().toString() + " 【 " + newReqBinArr.size() + " payloads has been scanned! 】");
    }


    private static List<JsonNode> jsonIterator(JsonNode rootNode) {
        List<JsonNode> res = new ArrayList<>();
        if (rootNode.isValueNode()) {
            return new ArrayList<>();
        }
        if (rootNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> it = rootNode.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> entry = it.next();
                if (entry.getValue().isValueNode()) {
                    ObjectMapper mapper = new ObjectMapper();
                    ObjectNode node = mapper.createObjectNode();
                    node.put("$557c56fe3", entry.getValue().asText());
                    JsonNode newRootNode = rootNode.deepCopy();
                    ((ObjectNode) newRootNode).replace(entry.getKey(), node);
                    res.add(newRootNode);
                    continue;
                }
                for (JsonNode newValue:
                        jsonIterator(entry.getValue())) {
                    ObjectNode newRootNode = rootNode.deepCopy();
                    newRootNode.replace(entry.getKey(), newValue);
                    res.add(newRootNode);
                }
            }
        } else if (rootNode.isArray() && rootNode.isContainerNode()) {
            int i = 0;
            for (JsonNode jsonNode : rootNode) {
                for (JsonNode newValue : jsonIterator(jsonNode)) {
                    ArrayNode newRootNode = rootNode.deepCopy();
                    newRootNode.set(i, newValue);
                    res.add(newRootNode);
                }
                i += 1;
            }
        }else{
            res = jsonIterator(rootNode);
        }
        return res;
    }

}
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}


