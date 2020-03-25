package dev.luckynetwork.alviann.vultrapiexecutor;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.luckynetwork.alviann.vultrapiexecutor.closer.Closer;
import dev.luckynetwork.alviann.vultrapiexecutor.command.Command;
import okhttp3.*;

import java.io.*;
import java.nio.file.Files;
import java.util.*;

public class VultrAPIExecutor {

    private static boolean RUNNING;

    private Gson gson;
    private JsonObject config;

    public void loadConfig() throws IOException {
        File file = new File("config.json");

        if (!file.exists()) {
            try (Closer closer = new Closer()) {
                ClassLoader classLoader = this.getClass().getClassLoader();
                InputStream stream = classLoader.getResourceAsStream("config.json");

                if (stream == null)
                    throw new IOException("Cannot load config.json file!");

                closer.add(stream);
                Files.copy(stream, file.toPath());
            }
        }

        try (Closer closer = new Closer()) {
            FileReader reader = closer.add(new FileReader(file));
            config = JsonParser.parseReader(reader).getAsJsonObject();
        }
    }

    public String[] handleCommand(String command, String apiKey, String firewallGroupId, String[] args) throws IOException {
        String url;
        FormBody formBody = null;

        switch (command) {
            case "firewall rule add": {
                formBody = new FormBody.Builder()
                        .add("FIREWALLGROUPID", firewallGroupId)
                        .add("direction", "in")
                        .add("ip_type", "v4")
                        .add("protocol", "tcp")
                        .add("subnet", args[0])
                        .add("subnet_size", "32")
                        .add("port", args[1])
                        .build();

                url = "https://api.vultr.com/v1/firewall/rule_create";
                break;
            }
            case "firewall rule remove": {
                formBody = new FormBody.Builder()
                        .add("FIREWALLGROUPID", firewallGroupId)
                        .add("rulenumber", args[0])
                        .build();

                url = "https://api.vultr.com/v1/firewall/rule_delete";
                break;
            }
            case "firewall rule list": {
                url = "https://api.vultr.com/v1/firewall/rule_list?FIREWALLGROUPID=" + firewallGroupId + "&direction=in&ip_type=v4";
                break;
            }

            case "firewall group list": {
                url = "https://api.vultr.com/v1/firewall/group_list";
                break;
            }

            default: {
                throw new IllegalArgumentException("Invalid command! Please check the command list on the config again!");
            }
        }

        OkHttpClient client = new OkHttpClient();
        Request.Builder builder = new Request.Builder()
                .url(url)
                .header("User-Agent", "Mozilla/5.0")
                .header("API-Key", apiKey)
                .get();

        if (formBody != null)
            builder.post(formBody);

        Request request = builder.build();
        String[] results = new String[2];

        try (Closer closer = new Closer()) {
            Response response = closer.add(client.newCall(request).execute());
            ResponseBody body = response.body();

            if (body == null)
                return new String[]{null, String.valueOf(response.code())};

            closer.add(body);

            String string = body.string();
            JsonElement result = JsonParser.parseString(string);

            results[0] = gson.toJson(result);
            results[1] = String.valueOf(response.code());
        }

        return results;
    }

    public boolean isStringEmpty(String str) {
        return str.trim().isEmpty() || str.trim().equals(" ") || str.length() == 0;
    }

    public boolean isInteger(String str) {
        return str.matches("^[0-9]+$");
    }

    public Command deserializeCommand() throws IllegalAccessException {
        String command = config.get("command").getAsString();
        List<String> args = new ArrayList<>();

        JsonObject rule = config.get("firewall-rule").getAsJsonObject();
        // JsonObject group = config.get("firewall-group").getAsJsonObject();

        switch (command.toLowerCase()) {
            case "firewall rule add": {
                JsonObject addCase = rule.get("add-case").getAsJsonObject();

                String subnet = addCase.get("ip-address").getAsString();
                String port = addCase.get("port").getAsString();

                if (this.isStringEmpty(subnet) || this.isStringEmpty(port))
                    throw new IllegalArgumentException("Invalid arguments!");

                args = Arrays.asList(subnet, port);
                break;
            }
            case "firewall rule remove": {
                JsonObject removeCase = rule.get("remove-case").getAsJsonObject();
                String ruleNumber = removeCase.get("rule-number").getAsString();

                if (this.isStringEmpty(ruleNumber))
                    throw new IllegalArgumentException("Invalid arguments!");
                if (!this.isInteger(ruleNumber))
                    throw new IllegalAccessException("Rule number must be an integer!");

                args = Collections.singletonList(ruleNumber);
                break;
            }
            case "firewall rule list":
            case "firewall group list": {
                break;
            }

            default: {
                throw new IllegalArgumentException("Invalid command! Please check the command list on the config again!");
            }
        }

        return new Command(command.toLowerCase(), args.toArray(new String[0]));
    }

    public void start() throws IOException, IllegalAccessException {
        long start = System.currentTimeMillis();

        this.gson = new Gson().newBuilder().setPrettyPrinting().create();
        this.loadConfig();

        String apiKey = config.get("vultr-api-key").getAsString();
        String firewallGroupId = config.get("firewall-group-id").getAsString();

        Command command = this.deserializeCommand();
        String[] results = this.handleCommand(command.getCommand(), apiKey, firewallGroupId, command.getArguments());

        long time = System.currentTimeMillis() - start;
        this.dumpResults(results[0], time, Integer.parseInt(results[1]));

        System.out.println("Execution time: " + time + " ms!");
        System.out.println("HTTP Response Code: " + results[1]);
        System.out.println("JSON Response: \n" + results[0]);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    public void dumpResults(String jsonResponse, long time, int codeResponse) {
        File dumpFile = new File("dump.txt");

        try (Closer closer = new Closer()) {
            if (!dumpFile.exists())
                dumpFile.createNewFile();

            FileWriter fileWriter = closer.add(new FileWriter(dumpFile));
            PrintWriter writer = closer.add(new PrintWriter(fileWriter));

            writer.println("Execution time: " + time + " ms!");
            writer.println("HTTP Response Code:" + codeResponse);
            writer.println("JSON Response:");

            if (jsonResponse != null)
                writer.println(jsonResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    public void dumpErrors(Exception ex) {
        File dumpFile = new File("errors.txt");

        try (Closer closer = new Closer()) {
            if (!dumpFile.exists())
                dumpFile.createNewFile();

            FileWriter fileWriter = closer.add(new FileWriter(dumpFile));
            PrintWriter writer = closer.add(new PrintWriter(fileWriter));

            writer.println(Arrays.toString(ex.getStackTrace()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        VultrAPIExecutor executor = new VultrAPIExecutor();

        try {
            executor.start();
        } catch (Exception ex) {
            executor.dumpErrors(ex);
        }

        if (RUNNING) return;

        InputStream stream = System.in;
        Scanner scanner = new Scanner(stream);

        while (scanner.hasNext()) {
            String line = scanner.nextLine();

            switch (line.toLowerCase()) {
                case "exit":
                case "close":
                case "shutdown": {
                    return;
                }
                case "reload": {
                    RUNNING = true;

                    try {
                        new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    main(args);

                    break;
                }
            }

        }
    }

}
