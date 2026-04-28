package org.zaproxy.addon.cwe400scanner;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.List;
import java.util.ArrayList;

public class Cwe400ConcurrentScanRule extends AbstractAppPlugin {

    private static final int PLUGIN_ID = 4000005; 
    private static final int MIN_LAG_THRESHOLD = 1500;
    private static final int LAG_MULTIPLIER = 5;

    @Override
    public int getId() { return PLUGIN_ID; }
    @Override
    public String getName() { return "CWE-400 Dynamic Load Scanner"; }
    @Override
    public String getReference() { return "https://owasp.org/Top10/A04_2021-Insecure_Design/"; }
    @Override
    public String getDescription() { return "Stress tests endpoints using dynamic thread stepping based on system & user limits."; }
    @Override
    public int getCategory() { return Category.SERVER; }
    @Override
    public String getSolution() { return "Implement rate limiting and optimize resource pool management."; }

    @Override
    public void scan() {
        if (isStop()) return;

        int userLimit = ExtensionCwe400Scanner.getUserMaxThreads();
        long maxMemoryBytes = Runtime.getRuntime().maxMemory();
        int ramSafetyLimit = (int) (maxMemoryBytes / (1024 * 1024 * 4));
        
        int finalMaxThreads = Math.min(userLimit, ramSafetyLimit);

        ExtensionCwe400Scanner.log("=========================================");
        ExtensionCwe400Scanner.log("[INIT] Target: " + getBaseMsg().getRequestHeader().getURI().toString());
        ExtensionCwe400Scanner.log("[INIT] System Safety Limit (RAM): " + ramSafetyLimit);
        ExtensionCwe400Scanner.log("[INIT] Practical Test Limit: " + finalMaxThreads);

        long baselineTime = 0;
        try {
            HttpMessage msg = getBaseMsg();
            sendAndReceive(msg, false, false);
            baselineTime = msg.getTimeElapsedMillis();
            ExtensionCwe400Scanner.log("[INFO] Baseline Response: " + baselineTime + "ms");
        } catch (Exception e) { return; }

        int currentThreads = 10; 
        boolean isVulnerable = false;
        boolean isRateLimited = false;

        while (currentThreads <= finalMaxThreads && !isVulnerable && !isRateLimited) {
            if (isStop()) break;

            ExtensionCwe400Scanner.log("\n[>>>] Testing: " + currentThreads + " concurrent requests...");
            
            ExecutorService executor = Executors.newFixedThreadPool(currentThreads);
            List<Callable<long[]>> tasks = new ArrayList<>();

            for (int i = 0; i < currentThreads; i++) {
                final int id = i;
                tasks.add(() -> {
                    HttpMessage attackMsg = getNewMsg();
                    String query = attackMsg.getRequestHeader().getURI().getQuery();
                    attackMsg.getRequestHeader().getURI().setEscapedQuery((query != null ? query + "&" : "") + "zap_ts=" + System.currentTimeMillis() + id);
                    try {
                        sendAndReceive(attackMsg, false, false);
                        return new long[] { attackMsg.getResponseHeader().getStatusCode(), attackMsg.getTimeElapsedMillis() };
                    } catch (Exception e) { return new long[] { 0, 99999 }; }
                });
            }

            try {
                List<Future<long[]>> results = executor.invokeAll(tasks);
                executor.shutdown();
                executor.awaitTermination(30, TimeUnit.SECONDS);

                long maxBatchTime = 0;
                for (Future<long[]> f : results) {
                    long[] res = f.get();
                    if (res[0] == 429 || res[0] == 503) isRateLimited = true;
                    if (res[1] > maxBatchTime) maxBatchTime = res[1];
                }

                ExtensionCwe400Scanner.log("   [-] Max Response: " + maxBatchTime + "ms");

                if (isRateLimited) {
                    ExtensionCwe400Scanner.log("[SAFE] HTTP 429/503 detected. Server has Rate Limiting.");
                    break;
                }

                if (maxBatchTime >= (baselineTime * LAG_MULTIPLIER) && maxBatchTime > MIN_LAG_THRESHOLD) {
                    isVulnerable = true;
                    ExtensionCwe400Scanner.log("[VULNERABLE] Breaking point found at " + currentThreads + " threads!");
                    raiseCweAlert(currentThreads, maxBatchTime, baselineTime);
                    break;
                }

                currentThreads *= 2;
                
            } catch (Exception e) { break; }
        }

        ExtensionCwe400Scanner.log("[END] Scan completed.");
    }

    private void raiseCweAlert(int threads, long lag, long baseline) {
        try {
            newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setName("CWE-400: Resource Exhaustion via Concurrent Requests")
                .setDescription("The server's response time degraded significantly under concurrent load.")
                .setOtherInfo("Baseline: " + baseline + "ms\nBreaking Point: " + threads + " threads\nMax Response: " + lag + "ms")
                .setMessage(getBaseMsg())
                .raise();
        } catch (Exception e) {}
    }
}