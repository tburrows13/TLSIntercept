package com.interceptiontest;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.Button;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.Scanner;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        runTests();

        Button button = findViewById(R.id.button);
        button.setOnClickListener(view -> runTests());
    }

    public void runTests() {
        basicFunc();
        Log.i("", "returnFunc returned: " + returnFunc());
        argFunc("My function argument");
        httpsFunc();
        socketFunc("data=2022-05-12;location=[50, 60],address=e@example.com\00\00");
        socketFunc("{\"key\": \"value\"}");
        socketFunc("qira\00{" +
                "  \"key\": \"value\"," +
                "  \"base64_encoded\": \"eyJiNjRrZXkiOiAiYjY0dmFsdWUifQ==\"," +
                "  \"extra_json\": {" +
                "    \"inner_key\": \"inner_value\"" +
                "  }" +
                "}");
        protobufFunc();
    }

    public void basicFunc() {
        Log.i("", "basicFunc called");
    }

    public String returnFunc() {
        Log.i("", "returnFunc called");
        return "Return Value";
    }

    public void argFunc(String arg) {
        Log.i("", "argFunc called with arg: " + arg);
    }

    public void httpsFunc() {
        Thread thread = new Thread(() -> {
            Log.i("", "httpsFunc called");
            try {
                URL url = new URL("https://example.com");
                URLConnection urlConnection = url.openConnection();
                InputStream inputStream = urlConnection.getInputStream();

                // From https://stackoverflow.com/a/35446009
                Scanner s = new Scanner(inputStream).useDelimiter("\\A");
                String result = s.hasNext() ? s.next() : "";
                Log.i("", result);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        thread.start();
    }

    public void socketFunc(String message) {
        Thread thread = new Thread(() -> {
            Log.i("", "socketFunc called");
            SocketFactory factory = SSLSocketFactory.getDefault();
            try {
                Socket socket = factory.createSocket("example.com", 443);
                OutputStream outputStream = socket.getOutputStream();
                outputStream.write(message.getBytes());
                outputStream.close();
                Log.i("", "socketFunc data written");
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        thread.start();
    }

    public void protobufFunc() {
        TestProtoBuf.Builder builder = TestProtoBuf.newBuilder();
        builder.setName("Test Name");
        builder.setId(123456);
        builder.setEmail("test@example.com");
        builder.setType(TestProtoBuf.TestEnum.OTP2);

        TestProtoBuf protoBuf = builder.build();

        Thread thread = new Thread(() -> {
            Log.i("", "protobufFunc called");
            SocketFactory factory = SSLSocketFactory.getDefault();
            try {
                Socket socket = factory.createSocket("example.com", 443);
                OutputStream outputStream = socket.getOutputStream();
                protoBuf.writeTo(outputStream);
                outputStream.close();
                Log.i("", "protobufFunc data written");
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        thread.start();
    }
}