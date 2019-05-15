package com.ahamove.cod;

import java.io.*;
import java.util.ArrayList;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.*;
import java.util.Date;
import io.github.cdimascio.dotenv.Dotenv;


/**
 * Sample App
 */
public class App
{
    private static Dotenv dotenv = Dotenv.load();
    private static final String BASE_URL = dotenv.get("BASE_URL");
    private static final String VERSION = "v1";
    private static final String PARTNER_ID = "local_dev"; // replace with your partner_id
    private static final String MY_LOCAL_SECRET_KEY = dotenv.get("MY_LOCAL_SECRET_KEY");
    private static String MY_LOCAL_PASS = dotenv.get("MY_LOCAL_PASS");
    private static final String APISTG_COD_PUBLIC_KEY = dotenv.get("APISTG_COD_PUBLIC_KEY");

    public static void main( String[] args )
    {
        String supplierId = "84762247148"; // sample phone number
        try {
            JSONArray orders = retrieveCodInfo(supplierId);
            // try to get first order then pay cod
            System.out.println("Pay cod for " + orders.getJSONObject(0).getString("id"));
            // pay Cod
            payCod(supplierId, orders.getJSONObject(0));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * payCod
     * @param supplierId
     * @param order
     * @throws Exception
     */
    public static void payCod(String supplierId, JSONObject order) throws Exception
    {
        JSONObject payload = new JSONObject();
        String transactionId =  Long.toString(new Date().getTime());
        payload.put("transaction_id", transactionId);
        payload.put("supplier_id", supplierId);
        payload.put("partner_id", PARTNER_ID);
        payload.put("order_id", order.getString("id"));
        payload.put("amount", order.getInt("total_cod"));
        System.out.print("payload");
        System.out.println(payload.toString());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            PGPHelper.getInstance().encryptAndSign(payload.toString().getBytes(), out);
        } catch (Exception e) {
            e.printStackTrace();
        }
        String encryptPayload = out.toString();
        System.out.println("encryptPayload");
        System.out.println(encryptPayload);

        String url = BASE_URL + VERSION + "/cod/pay";

        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        //add request header
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/pgp-encrypted");

        OutputStream os = con.getOutputStream();
        OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8");
        osw.write(encryptPayload);
        osw.flush();
        osw.close();
        os.close();

        System.out.println("\nSending 'POST' request to URL : " + url);

        int responseCode = con.getResponseCode();
        System.out.println("Response Code : " + responseCode);

        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String decryptedResult = decrypt(bufferedReader);
        System.out.println(decryptedResult);

        con.disconnect();

    }

    /**
     * retrieveCodInfo
     * @param supplierId
     * @return
     * @throws Exception
     */
    public static JSONArray retrieveCodInfo(String supplierId) throws Exception
    {
        String url =
                BASE_URL + VERSION + "/cod/retrieve_info?partner_id=" + PARTNER_ID + "&supplier_id=" + supplierId;

        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        int responseCode = con.getResponseCode();
        System.out.println("\nSending 'GET' request to URL : " + url);
        System.out.println("Response Code : " + responseCode);

        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String decryptedResult = decrypt(bufferedReader);
        con.disconnect();

        JSONArray orders = new JSONArray(decryptedResult);

        return orders;
    }

    /**
     * decrypt
     * @param in
     * @return
     * @throws Exception
     */
    public static String decrypt(BufferedReader in) throws Exception
    {
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        String responseData = response.toString();

        JSONObject jsonObject = new JSONObject(responseData);
        String encryptData = jsonObject.get("data").toString();

        PGPHelper.init(MY_LOCAL_SECRET_KEY, APISTG_COD_PUBLIC_KEY, MY_LOCAL_PASS);
        ByteArrayOutputStream desStream = new ByteArrayOutputStream();
        PGPHelper.getInstance().decryptAndVerifySignature(encryptData.getBytes(), desStream);

        return desStream.toString();
    }
}
