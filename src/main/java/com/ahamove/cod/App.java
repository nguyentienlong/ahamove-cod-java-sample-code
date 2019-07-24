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
    private static final String PARTNER_ID = dotenv.get("PARTNER_ID");
    private static final String MY_LOCAL_SECRET_KEY = dotenv.get("MY_LOCAL_SECRET_KEY");
    private static String MY_LOCAL_PASS = dotenv.get("MY_LOCAL_PASS");
    private static final String APISTG_COD_PUBLIC_KEY = dotenv.get("APISTG_COD_PUBLIC_KEY");

    public static void main( String[] args )
    {
        String supplierId = "84762247148"; // sample phone number
        try {
            JSONArray orders = retrieveCodInfo(supplierId);
            // try to get first order then pay cod
            System.out.println("## Pay cod for " + orders.getJSONObject(0).getString("id"));
            // pay Cod
            payCod(supplierId, orders.getJSONObject(0));

            // top up for supplier type
            System.out.println("## Top up for supplier " + supplierId + " amount " + 10000);
            topUp(supplierId, "supplier", 10000);

            // top up for user type
            System.out.println("## Top up for user " + supplierId + " amount " + 20000);
            topUp(supplierId, "user", 20000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * topUp
     * @param String phoneNumber
     * @param String userType
     * @param int amount
     * @throws Exception
     */
    private static void topUp(String phoneNumber, String userType, int amount) throws Exception
    {
        JSONObject payload = new JSONObject();
        String transactionId =  Long.toString(new Date().getTime());
        payload.put("transaction_id", transactionId);
        payload.put("phone_number", phoneNumber);
        payload.put("user_type", userType);
        payload.put("partner_id", PARTNER_ID);
        payload.put("amount", amount);

        String url = BASE_URL + VERSION + "/cod/top_up";
        sendPostRequest(payload, url);
    }

    /**
     * sendPostRequest
     * @param JSONObject payload
     * @param String url
     * @throws Exception
     */
    private static void sendPostRequest(JSONObject payload, String url) throws Exception{
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
     * payCod
     * @param String supplierId
     * @param JSONObject order
     * @throws Exception
     */
    private static void payCod(String supplierId, JSONObject order) throws Exception
    {
        JSONObject payload = new JSONObject();
        String transactionId =  Long.toString(new Date().getTime());
        payload.put("transaction_id", transactionId);
        payload.put("supplier_id", supplierId);
        payload.put("partner_id", PARTNER_ID);
        payload.put("order_id", order.getString("id"));
        payload.put("amount", order.getInt("total_cod"));

        String url = BASE_URL + VERSION + "/cod/pay";
        sendPostRequest(payload, url);
    }

    /**
     * retrieveCodInfo
     * @param String supplierId
     * @return
     * @throws Exception
     */
    private static JSONArray retrieveCodInfo(String supplierId) throws Exception
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

        return new JSONArray(decryptedResult);
    }

    /**
     * decrypt
     * @param BufferedReader in
     * @return
     * @throws Exception
     */
    private static String decrypt(BufferedReader in) throws Exception
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
