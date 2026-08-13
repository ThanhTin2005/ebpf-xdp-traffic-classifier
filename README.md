# eBPF-XDP Traffic Classifier (Decision Tree IDS)

> **Trạng thái dự án:** 🚧 Đang phát triển (Work In Progress)

Dự án này là một Hệ thống phát hiện xâm nhập (Intrusion Detection System - IDS) cấp thấp, kết hợp sức mạnh xử lý tốc độ siêu cao của **eBPF/XDP** ở tầng kernel và khả năng nhận diện của mô hình học máy **Decision Tree**. 

## 💡 Ý tưởng cốt lõi

Thông thường, các hệ thống tường lửa hoặc phân tích mạng phải đợi gói tin đi sâu vào TCP/IP stack của hệ điều hành mới có thể xử lý, gây tốn kém tài nguyên CPU. Dự án này giải quyết bài toán đó bằng cách chặn đứng các gói tin độc hại ngay tại cửa ngõ giao tiếp mạng (Network Interface).

Cơ chế hoạt động bao gồm 2 giai đoạn chính:
1. **Machine Learning (User-Space):** Sử dụng Python và `scikit-learn` để huấn luyện một mô hình Cây quyết định (Decision Tree) có giới hạn độ sâu. Mô hình này sau đó sẽ tự động xuất ra một bộ luật phân loại dạng `if-else` thuần túy bằng ngôn ngữ C.
2. **Packet Filtering (Kernel-Space):** Mã nguồn C được biên dịch thành eBPF bytecode và nạp vào XDP. Gói tin vừa chạm vào card mạng sẽ được trích xuất Header (lấy Port, Length, Protocol...) và đối chiếu với bộ luật trên để ra quyết định:
   * `XDP_PASS`: Gói tin an toàn, cho phép đi qua.
   * `XDP_DROP`: Gói tin độc hại, tiêu diệt ngay từ vòng gửi xe.

## 📂 Cấu trúc Repository hiện tại

* `train_dt.py`: Script Python để tạo dữ liệu, huấn luyện mô hình và sinh code C tự động.
* `xdp_dt_ids.c`: Chương trình XDP chính làm nhiệm vụ bóc tách gói tin và nhúng logic Decision Tree.
* Các file lab cơ sở (`xdp_hello.c`, `xdp_drop_port.c`) phục vụ việc nghiên cứu kiến trúc eBPF.

## 🚀 Lộ trình hoàn thiện (Roadmap)
Dự án đang trong quá trình phát triển, các mục tiêu tiếp theo bao gồm:
- [x] Hoàn thiện pipeline sinh code C từ mô hình Machine Learning.
- [x] Tích hợp logic Decision Tree vào chương trình XDP và vượt qua eBPF Verifier.
- [ ] Bổ sung eBPF Maps để theo dõi trạng thái luồng mạng (Flow-tracking).
- [ ] Chạy thử nghiệm đánh chặn traffic độc hại (hping3/curl).
- [ ] Benchmark và đo lường hiệu năng xử lý (Packets-per-second).

## 👨‍💻 Tác giả

* **Phạm Thành Tín** 
* Sinh viên Kỹ thuật Máy tính - Đại học Bách khoa Hà Nội (HUST).
