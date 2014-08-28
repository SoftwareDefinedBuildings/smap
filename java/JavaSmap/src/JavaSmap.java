import java.io.*;
import java.net.*;
import java.util.ArrayList;

import org.json.simple.JSONArray;
import org.json.simple.parser.*;

public class JavaSmap {
  
  public URL archiver;
  public String key;

  public JavaSmap(String archiverUrl, String key, boolean priv, double timeout) throws Exception{
    URL url = new URL(archiverUrl + "?key='" + key + "'"); 
    this.archiver = url;
    this.key = key;
  }
  public JavaSmap(String archiverUrl) throws Exception{
    this(archiverUrl, "", false, 50.0);
  }

  private String postQuery(String q) throws Exception{
    System.out.println(q);
    HttpURLConnection connection = (HttpURLConnection) this.archiver.openConnection();           
    connection.setDoOutput(true);
    connection.setDoInput(true);
    connection.setRequestMethod("POST"); 
    connection.setRequestProperty("Content-Type", "text/plain"); 
    connection.setRequestProperty("charset", "utf-8");
    
    DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
    wr.writeBytes(q);
    wr.flush();
    wr.close();
    System.out.println(connection.getResponseCode()+" "+connection.getResponseMessage());
    
    String result = "";
    String line;
    InputStream stream = connection.getInputStream();
    InputStreamReader isReader = new InputStreamReader(stream);
    BufferedReader br = new BufferedReader(isReader);
    while ((line = br.readLine()) != null) {
          result += line;
      }
        connection.disconnect();
        return result;   
  }
  
  private JSONArray parseJSONArray(String r) throws ParseException{
      JSONParser parser = new JSONParser();
      Object obj = parser.parse(r);
      JSONArray arr = (JSONArray)obj;
      return arr;   
  }
  
  private String _data(String selector, String restrict, long limit, long streamlimit) throws Exception{
    String q = "select data " + selector + 
           " limit " + limit + 
           " streamlimit " + streamlimit + 
           " where " + restrict;
        return postQuery(q);
  }
  
  public JSONArray next(String restrict, long ref, long limit, long streamlimit) throws Exception{
    String selector = "after " + ref * 1000;
    String r =  _data(selector, restrict, limit, streamlimit);
    return parseJSONArray(r);
  }
  
    public JSONArray prev(String restrict, long ref, long limit, long streamlimit) throws Exception{
    String selector = "before " + ref * 1000;
    String r =  _data(selector, restrict, limit, streamlimit);
    return parseJSONArray(r);
  }
    
  public JSONArray latest(String restrict, long limit, long streamlimit) throws Exception{
      String selector = "before now";
      String r = _data(selector, restrict, limit, streamlimit);
      return parseJSONArray(r);
  }
    
  public JSONArray data(String restrict, long start, long end, long limit) throws Exception{
      String selector = "in (" + start + ", " + end + ")";
      String r = _data(selector, restrict, limit, 1000L);
      return parseJSONArray(r);
  }
  
  public JSONArray data_uuid(ArrayList<String> uuids, long start, long end, long limit) throws Exception{
    String selector = "in (" + start + ", " + end + ")";
    String restrict = "";
    int L = uuids.size();
    for (int i = 0; i < L - 1 ; i++){
      restrict = restrict + "uuid='" + uuids.get(i) + "' or ";
    }
    restrict = restrict + "uuid='" + uuids.get(L-1) + "'";
    String r = _data(selector, restrict, limit, 1000L);
    return parseJSONArray(r);
  }
  
  public JSONArray tags(String restrict, String tags) throws Exception{
      String q = "select " + tags + " where " + restrict;
      String r = postQuery(q);
      return parseJSONArray(r);
  }

  @SuppressWarnings("unchecked")
  public static void main(String[] args) throws Exception {

    String archiverUrl = "http://new.openbms.org/backend/api/query"; 

    JavaSmap js = new JavaSmap(archiverUrl);
    long end = System.currentTimeMillis();
    long start = end - 300000;

    // test postQuery
    // String result = postQuery("select distinct", js.archiver);

    // test tags
    //JSONArray result = js.tags("Metadata/Extra/Type = 'oat'", "Metadata/Extra/Type");

    // test latest, next, prev
    //JSONArray result = js.latest("Metadata/Extra/Type = 'oat'", 1, 1L);
    //JSONArray result = js.next("Metadata/Extra/Type = 'oat'", 1381877084L, 1L, 1L);
    //JSONArray result = js.prev("Metadata/Extra/Type = 'oat'", 1381877084L, 1L, 1L);

    // test data, data_uuid
    JSONArray result = js.data("Metadata/Extra/Type = 'oat'", start, end, 1000L);
    //ArrayList<String> uuids = new ArrayList<String>();
    //uuids.add("395005af-a42c-587f-9c46-860f3061ef0d");
    //uuids.add("9f091650-3973-5abd-b154-cee055714e59");
    //JSONArray result = js.data_uuid(uuids, start, end, 10000L);

    System.out.println(result);
    
  }
}
