#### Build ZAP add-ons

### Bước 1: Chuẩn bị môi trường & Mã nguồn ZAP

Trước khi code, bạn cần có một môi trường biên dịch ZAP cục bộ.

1. **Cài đặt công cụ:** Đảm bảo máy đã cài đặt **Git** và **Java JDK 17**.
    
2. **Clone mã nguồn:** Mở terminal và tải 2 repository cốt lõi vào cùng một thư mục làm việc (ví dụ: `~/zap-dev`):
    
    Bash
    
    ```
    git clone https://github.com/zaproxy/zaproxy.git
    git clone https://github.com/zaproxy/zap-extensions.git
    ```
    
3. **Cài đặt Mandatory Add-ons:** Di chuyển vào `zap-extensions` và chạy lệnh Gradle để copy các thành phần bắt buộc sang bộ nguồn chính:
    
    Bash
    
    ```
    cd zap-extensions
    ./gradlew copyMandatoryAddOns
    ```
    

### Bước 2: Tạo bộ khung Add-on mới (Scaffolding)

Chúng ta sẽ nhân bản add-on `simpleexample` có sẵn để làm khung cho add-on `cwe400scanner`.

1. **Copy thư mục:** Đứng tại `zap-extensions`, chạy lệnh:
    
    Bash
    
    ```
    cp -R addOns/simpleexample addOns/cwe400scanner
    ```
    
2. **Đổi tên file cấu hình:**
    
    Bash
    
    ```
    mv addOns/cwe400scanner/simpleexample.gradle.kts addOns/cwe400scanner/cwe400scanner.gradle.kts
    ```
    
3. **Cập nhật nội dung `cwe400scanner.gradle.kts`:** Mở file này và sửa lại thông tin:
    
    Kotlin
    
    ```
    version = "0.0.1"
    description = "Active Scan Rule for CWE-400 Concurrent Testing (Phase 2)"
    
    zapAddOn {
        addOnName.set("CWE-400 Concurrent Scanner")
        zapVersion.set("2.10.0") // Điều chỉnh theo version ZAP hiện tại của repo
        manifest {
            author.set("Your Name")
        }
    }
    ```
    
4. **Khai báo Add-on:** Mở file `settings.gradle.kts` nằm ở thư mục gốc của `zap-extensions`, tìm đến block `addOns` và thêm `cwe400scanner` vào danh sách.
    

### Bước 3: Lập trình Logic Đa luồng (Java Core)

Đây là phần lõi. Bạn cần xóa/đổi tên các file Java mẫu và tạo một Active Scan Rule kế thừa từ API của ZAP.

1. **Tạo cấu trúc Package mới:** Trong thư mục `addOns/cwe400scanner/src/main/java/org/zaproxy/addon/`, đổi tên thư mục `simpleexample` thành `cwe400scanner`.
    
2. **Tạo Class Quét (Ví dụ: `Cwe400ConcurrentScanRule.java`):** Xóa file mẫu và tạo class mới kế thừa `AbstractAppPlugin` (dùng để quét toàn bộ endpoint) hoặc `AbstractAppParamPlugin` (nếu muốn fuzz vào từng tham số). Dưới đây là bộ khung code Java thực thi ExecutorService:
    
    Java
    
    ```
    package org.zaproxy.addon.cwe400scanner;
    
    import org.parosproxy.paros.network.HttpMessage;
    import org.zaproxy.zap.extension.ascan.AbstractAppPlugin;
    import java.util.concurrent.ExecutorService;
    import java.util.concurrent.Executors;
    import java.util.concurrent.Callable;
    import java.util.List;
    import java.util.ArrayList;
    import java.util.concurrent.Future;
    
    public class Cwe400ConcurrentScanRule extends AbstractAppPlugin {
    
        private static final int PLUGIN_ID = 4000005; // Đảm bảo ID không trùng lặp
        private static final int CONCURRENT_THREADS = 20; 
    
        @Override
        public int getId() {
            return PLUGIN_ID;
        }
    
        @Override
        public String getName() {
            // Tên lấy từ file properties
            return getMessageString("cwe400scanner.name"); 
        }
    
        @Override
        public void scan() {
            // Bỏ qua nếu user bấm Stop
            if (isStop()) return;
    
            HttpMessage msg = getBaseMsg();
    
            // Đoạn logic ExecutorService bạn đã định hình trước đó
            ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_THREADS);
            List<Callable<Long>> tasks = new ArrayList<>();
    
            for (int i = 0; i < CONCURRENT_THREADS; i++) {
                tasks.add(() -> {
                    HttpMessage attackMsg = getNewMsg();
                    // Thêm cache-buster tại đây để chống deduplication
                    sendAndReceive(attackMsg, false, false);
                    return attackMsg.getTimeElapsedMillis();
                });
            }
    
            try {
                List<Future<Long>> results = executor.invokeAll(tasks);
                // Lặp qua results để đánh giá timeTaken và Status Code
                // Nếu phát hiện Lag đột biến -> Kích hoạt raiseAlert()
    
                /* Mẫu gọi Alert:
                newAlert()
                    .setRisk(Alert.RISK_HIGH)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setDescription(getMessageString("cwe400scanner.desc"))
                    .raise();
                */
    
            } catch (Exception e) {
                // Xử lý lỗi luồng
            } finally {
                executor.shutdown();
            }
        }
    }
    ```
    

### Bước 4: Cấu hình Đa ngôn ngữ (Messages.properties)

ZAP yêu cầu mọi chuỗi văn bản hiển thị ra UI phải nằm trong file cấu hình để hỗ trợ đa ngôn ngữ.

1. Đi tới `addOns/cwe400scanner/src/main/resources/org/zaproxy/addon/cwe400scanner/resources/`.
    
2. Đổi tên file (nếu cần) thành `Messages.properties`.
    
3. Khai báo các biến văn bản:
    
    Properties
    
    ```
    cwe400scanner.name=CWE-400 Missing Rate Limiting (Concurrent Load)
    cwe400scanner.desc=The endpoint failed to handle concurrent requests securely, leading to Resource Exhaustion.
    cwe400scanner.solution=Implement strict rate limiting and concurrency locks.
    ```
    

### Bước 5: Biên dịch và Chạy kiểm tra

Sau khi hoàn thiện code, bạn tiến hành đóng gói add-on và bơm thẳng vào bản build của ZAP.

1. **Biên dịch và Copy Add-on:** Đứng tại thư mục `zap-extensions`, chạy lệnh:
    
    Bash
    
    ```
    ./gradlew addOns:cwe400scanner:copyZapAddOn
    ```
    
2. **Khởi chạy ZAP từ mã nguồn:** Di chuyển sang thư mục `zaproxy` (đã clone ở Bước 1) và khởi động ZAP:
    
    Bash
    
    ```
    cd ../zaproxy
    ./gradlew run
    ```
    
1. Màn hình ZAP sẽ mở ra với dòng chữ "Dev Build". Bạn vào phần cấu hình Scan Policy của Active Scan, tìm tên Add-on "CWE-400 Concurrent Scanner" vừa tạo để kích hoạt và quét thử nghiệm.