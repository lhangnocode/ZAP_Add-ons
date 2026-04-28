### Run ZAP add-ons

Bây giờ môi trường của bạn đã chuẩn, hãy quay lại giải quyết dứt điểm Add-on nhé:

**1. Build Add-on:** Đứng ở thư mục gốc `zap-extensions`, chạy lại lệnh lúc nãy:

Bash

```
./gradlew addOns:cwe400scanner:copyZapAddOn
```

_(Lần này chắc chắn nó sẽ chạy đến `BUILD SUCCESSFUL`)_

**2. Copy các Add-on bắt buộc (Nếu bạn chưa làm trước đó):** Vẫn đứng ở `zap-extensions`, chạy thêm lệnh này để đảm bảo ZAP không bị thiếu file cốt lõi:

Bash

```
./gradlew copyMandatoryAddOns
```

**3. Khởi chạy ZAP:** Cuối cùng, nhảy sang thư mục `zaproxy` và gọi ZAP lên:

Bash

```
cd ../zaproxy
./gradlew run
```