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
    public String getDescription() { return "Stress tests endpoints checking for high latency, timeouts, and HTTP 500 crashes."; }
    @Override
    public int getCategory() { return Category.SERVER; }
    @Override
    public String getSolution() { return "Implement rate limiting, optimize resource pools, and handle timeouts gracefully."; }

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
        } catch (Exception e) { 
            ExtensionCwe400Scanner.log("[ERROR] Cannot reach target for baseline.");
            return; 
        }

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
                    } catch (Exception e) { 
                        // Trả về status 0 để báo hiệu lỗi mạng/timeout
                        return new long[] { 0, 99999 }; 
                    }
                });
            }

            try {
                List<Future<long[]>> results = executor.invokeAll(tasks);
                executor.shutdown();
                executor.awaitTermination(30, TimeUnit.SECONDS);

                long maxBatchTime = 0;
                int count500 = 0;
                int countTimeout = 0;

                for (Future<long[]> f : results) {
                    long[] res = f.get();
                    int status = (int) res[0];
                    long time = res[1];

                    if (status == 429 || status == 503) isRateLimited = true;
                    if (status == 500) count500++;
                    if (status == 0) countTimeout++;
                    
                    // Chỉ lấy max time của các request thành công (bỏ qua giá trị 99999 ảo)
                    if (status != 0 && time > maxBatchTime) {
                        maxBatchTime = time;
                    }
                }

                ExtensionCwe400Scanner.log("   [-] Max Response: " + maxBatchTime + "ms | 500s: " + count500 + " | Timeouts: " + countTimeout);

                if (isRateLimited) {
                    ExtensionCwe400Scanner.log("[SAFE] HTTP 429/503 detected. Server has Rate Limiting.");
                    break;
                }

                // KIỂM TRA 3 TRƯỜNG HỢP GÂY SẬP (Lỗi 500, Timeout, Lag)
                String vulnerabilityReason = null;
                
                if (count500 > 0) {
                    vulnerabilityReason = "Server crashed and returned HTTP 500 Internal Server Error (" + count500 + " times).";
                } else if (countTimeout > 0) {
                    vulnerabilityReason = "Server stopped responding/Timed out (" + countTimeout + " dropped requests).";
                } else if (maxBatchTime >= (baselineTime * LAG_MULTIPLIER) && maxBatchTime > MIN_LAG_THRESHOLD) {
                    vulnerabilityReason = "Response time degraded massively to " + maxBatchTime + "ms.";
                }

                if (vulnerabilityReason != null) {
                    isVulnerable = true;
                    ExtensionCwe400Scanner.log("[VULNERABLE] Breaking point found at " + currentThreads + " threads!");
                    ExtensionCwe400Scanner.log("   [!] Reason: " + vulnerabilityReason);
                    raiseCweAlert(currentThreads, maxBatchTime, baselineTime, vulnerabilityReason);
                    break;
                }

                currentThreads *= 2;
                
            } catch (Exception e) { break; }
        }

        ExtensionCwe400Scanner.log("[END] Scan completed.");
    }

    private void raiseCweAlert(int threads, long lag, long baseline, String reason) {
        try {
            newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setName("CWE-400: Uncontrolled Resource Consumption")
                .setDescription("The server failed to handle concurrent load safely. Reason: " + reason)
                .setOtherInfo("Baseline Time: " + baseline + "ms\nBreaking Point: " + threads + " threads\nMax Recorded Lag: " + lag + "ms\nDetail: " + reason)
                .setMessage(getBaseMsg())
                .raise();
        } catch (Exception e) {}
    }
}