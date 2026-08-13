# 法國巴黎親子自由行｜GitHub Pages 加密版

這個 repo 是 public，但行程內容不以明文儲存在 repo 裡。

## 運作方式

- `index.html`：公開的解鎖頁面與版面
- `style.css`：公開樣式
- `encrypted-data.json`：加密後的行程內容

使用者輸入密碼後，瀏覽器會在本機用 WebCrypto 解密內容並顯示每日行程。

## 注意

- 密碼不可放進 repo。
- GitHub Pages 本身沒有密碼保護；這是「前端資料加密」方案。
- 不建議放高度敏感資料，例如護照、信用卡、完整住址。
- 若忘記密碼，需要用原始資料重新產生 `encrypted-data.json`。

## GitHub Pages

網站：

```text
https://erwin071.github.io/france-trip-itinerary/
```
