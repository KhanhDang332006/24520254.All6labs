### 4.2. Bảng Số Liệu Thống Kê Lab 1 (Mốc 8MB)

**Bảng: Hiệu năng mã hóa và giải mã AES trên Windows 11 (MinGW)**
| Chế độ | Thao tác | Latency (Mean ± 95% CI) | Median (ms) | StdDev (ms) | Thông lượng (MB/s) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AES-CTR** | Encrypt | 2449.857 ± 5.036 ms | 2446.691 ms | 14.072 ms | 3265.5 MB/s |
| **AES-CTR** | Decrypt | 2450.584 ± 3.967 ms | 2448.237 ms | 11.085 ms | 3264.53 MB/s |
| **AES-CBC** | Encrypt | 7836.732 ± 535.843 ms | 7581.81 ms | 1497.414 ms | 1020.83 MB/s |
| **AES-CBC** | Decrypt | 58524.746 ± 108812.679 ms | 3012.056 ms | 304077.342 ms | 136.69 MB/s |
| **AES-OFB** | Encrypt | 7660.311 ± 8.79 ms | 7657.445 ms | 24.563 ms | 1044.34 MB/s |
| **AES-OFB** | Decrypt | 9729.354 ± 3995.407 ms | 7662.454 ms | 11165.175 ms | 822.25 MB/s |
| **AES-CFB** | Encrypt | 7433.316 ± 10.411 ms | 7425.246 ms | 29.093 ms | 1076.24 MB/s |
| **AES-CFB** | Decrypt | 4686.937 ± 2387.669 ms | 3461.604 ms | 6672.348 ms | 1706.87 MB/s |
| **AES-XTS** | Encrypt | 6917.967 ± 28.815 ms | 6898.966 ms | 80.524 ms | 1156.41 MB/s |
| **AES-XTS** | Decrypt | 6864.126 ± 14.185 ms | 6856.227 ms | 39.639 ms | 1165.48 MB/s |
| **AES-ECB** | Encrypt | 2290.564 ± 28.258 ms | 2266.415 ms | 78.967 ms | 3492.59 MB/s |
| **AES-ECB** | Decrypt | 4430.156 ± 4181.641 ms | 2262.931 ms | 11685.609 ms | 1805.81 MB/s |
| **AES-GCM** | Encrypt | 3953.781 ± 114.217 ms | 3894.463 ms | 319.179 ms | 2023.38 MB/s |
| **AES-GCM** | Decrypt | 3572.156 ± 90.18 ms | 3563.336 ms | 252.008 ms | 2239.54 MB/s |
| **AES-CCM** | Encrypt | 8997.076 ± 158.208 ms | 9002.142 ms | 442.113 ms | 889.18 MB/s |
| **AES-CCM** | Decrypt | 9005.273 ± 13.182 ms | 8993.204 ms | 36.836 ms | 888.37 MB/s |

---

**Bảng: Hiệu năng mã hóa và giải mã AES trên Linux Ubuntu LTS (GCC)**
| Chế độ | Thao tác | Latency (Mean ± 95% CI) | Median (ms) | StdDev (ms) | Thông lượng (MB/s) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AES-CTR** | Encrypt | 2789.098 ± 28.357 ms | 2771.952 ms | 79.243 ms | 2868.31 MB/s |
| **AES-CTR** | Decrypt | 2904.74 ± 72.508 ms | 2825.458 ms | 202.624 ms | 2754.12 MB/s |
| **AES-CBC** | Encrypt | 7840.079 ± 26.59 ms | 7813.408 ms | 74.305 ms | 1020.4 MB/s |
| **AES-CBC** | Decrypt | 2836.36 ± 53.591 ms | 2814.493 ms | 149.761 ms | 2820.52 MB/s |
| **AES-OFB** | Encrypt | 7836.41 ± 32.269 ms | 7836.42 ms | 90.177 ms | 1020.88 MB/s |
| **AES-OFB** | Decrypt | 7832.118 ± 23.333 ms | 7828.472 ms | 65.204 ms | 1021.44 MB/s |
| **AES-CFB** | Encrypt | 7386.679 ± 14.927 ms | 7382.728 ms | 41.714 ms | 1083.03 MB/s |
| **AES-CFB** | Decrypt | 3579.079 ± 47.682 ms | 3565.614 ms | 133.246 ms | 2235.21 MB/s |
| **AES-XTS** | Encrypt | 6328.681 ± 93.012 ms | 6252.959 ms | 259.922 ms | 1264.09 MB/s |
| **AES-XTS** | Decrypt | 6319.06 ± 74.074 ms | 6251.309 ms | 207.0 ms | 1266.01 MB/s |
| **AES-ECB** | Encrypt | 2182.6 ± 31.79 ms | 2157.185 ms | 88.838 ms | 3665.35 MB/s |
| **AES-ECB** | Decrypt | 2244.331 ± 35.491 ms | 2219.544 ms | 99.179 ms | 3564.54 MB/s |
| **AES-GCM** | Encrypt | 3386.049 ± 28.434 ms | 3355.525 ms | 79.458 ms | 2362.64 MB/s |
| **AES-GCM** | Decrypt | 3260.524 ± 44.695 ms | 3226.486 ms | 124.9 ms | 2453.59 MB/s |
| **AES-CCM** | Encrypt | 8417.895 ± 58.412 ms | 8393.25 ms | 163.232 ms | 950.36 MB/s |
| **AES-CCM** | Decrypt | 8681.333 ± 42.444 ms | 8607.734 ms | 118.609 ms | 921.52 MB/s |

---

