# 法國巴黎親子自由行｜GitHub Pages 公開版

這是一個靜態旅遊行程網站，資料來源為 Google Sheet `Travel plan` 的 `france` tab，已整理成公開分享用資料。

## 隱私原則

此版本只保留：

- 每日行程摘要
- 景點名稱
- 交通建議
- 訂票提醒類型
- 預算區間
- 公開 Google Maps 搜尋連結

不應包含：

- 訂房確認碼
- 航班 PNR / 訂位代碼
- 電話、Email
- 護照、生日
- 信用卡或付款資訊
- 完整私人住宿地址
- 私人 Google Drive / Docs 連結

## 本機預覽

因為頁面會讀取 `itinerary.json`，建議用簡單 HTTP server 預覽：

```bash
cd france-trip-itinerary
python3 -m http.server 8000
```

打開：

```text
http://localhost:8000
```

## 發布到 GitHub Pages

```bash
git init
git add .
git commit -m "Initial France itinerary site"
git branch -M main
git remote add origin https://github.com/YOUR_ACCOUNT/france-trip-itinerary.git
git push -u origin main
```

然後到 GitHub：

```text
Settings → Pages → Build and deployment → Deploy from a branch → main / root
```

網站網址會是：

```text
https://YOUR_ACCOUNT.github.io/france-trip-itinerary/
```
