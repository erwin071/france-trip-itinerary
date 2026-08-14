# 法國巴黎親子自由行｜GitHub Pages 加密版

這個 repo 可以維持 public，但行程內容不以明文儲存在 repo 裡。

網站：

```text
https://erwin071.github.io/france-trip-itinerary/
```

## 目前加密方式

目前使用：

```text
KDF: PBKDF2-SHA256
Iterations: 250000
Cipher: AES-GCM 256-bit
IV: 96-bit random IV
Tag: 128-bit authentication tag
```

`encrypted-data.json` 會公開包含：

```json
{
  "version": 2,
  "alg": "AES-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 250000,
  "salt": "...",
  "iv": "...",
  "tagLength": 128,
  "ciphertext": "...",
  "tag": "..."
}
```

這些欄位都可以公開；真正不能公開的是密碼。

## 解鎖流程

網站不是把密碼跟 repo 裡的 hash 比對，而是：

```text
使用者輸入密碼
→ 瀏覽器用 password + salt + iterations 跑 PBKDF2-SHA256
→ 得到 AES-GCM key
→ 嘗試解密 encrypted-data.json
→ 解密與 tag 驗證成功才顯示行程
```

所以 repo 裡沒有存正確密碼，也沒有存密碼 hash。

## 為什麼 repo public 還能保護內容？

repo public 時，別人可以看到：

- `index.html`
- `style.css`
- `encrypted-data.json`
- 解密流程程式碼

但只要密碼沒有公開，別人只有密文，無法直接還原行程內容。

安全性主要取決於密碼強度。請使用隨機長密碼，不要使用：

```text
paris2027
france
123456
ivantrip
```

## 維護注意事項

- 密碼不可 commit 進 repo。
- 明文行程不可 commit 進 repo。
- 若要更新行程，請從私有來源重新產生明文 payload，再用密碼重新產生 `encrypted-data.json`。
- 若忘記密碼，無法從 `encrypted-data.json` 還原，只能用原始行程資料重新加密。
- 不建議放高度敏感資料，例如護照、信用卡、完整住址。

## 重新加密概念

流程：

```text
1. 準備明文 payload JSON
2. 選定密碼，密碼不要寫進 repo
3. 產生 random salt 與 random IV
4. PBKDF2-SHA256(password, salt, 250000) → 256-bit key
5. AES-GCM encrypt(payload, key, iv) → ciphertext + tag
6. 覆蓋 encrypted-data.json
7. git commit / push
```

此 repo 內有 `scripts/encrypt-gcm.pl` 作為目前環境用的加密輔助腳本；它不包含密碼。

## CI：敏感資訊掃描

每次 push / pull request 都會跑 GitHub Actions；正式 GitHub Pages 部署會等敏感資訊掃描通過後才執行：

```text
.github/workflows/sensitive-scan.yml
```

CI 會做兩件事：

1. 掃描 public repo 檔案，確認沒有把密碼或明文行程細節 commit 進去。
2. 用 GitHub Secret `ITINERARY_PASSWORD` 解密 `encrypted-data.json`，再掃描解密後的網站 payload，確認沒有 PNR、booking reference、ticket number、email、電話、護照、信用卡或私人 Google Docs/Sheets 連結等敏感資訊。

需要在 GitHub repo 設定 secret：

```text
Settings → Secrets and variables → Actions → New repository secret
Name: ITINERARY_PASSWORD
Value: 行程解鎖密碼
```

可選擇再加一個 secret：

```text
Name: SENSITIVE_TERMS
Value: 每行一個禁止出現在網站裡的敏感字串，例如 booking reference、ticket number、會員號碼等
```

注意：`SENSITIVE_TERMS` 不要 commit 到 repo，請只放 GitHub Secret。

### 部署 gate

GitHub Pages 已改成 GitHub Actions 部署模式，不再直接從 `main / root` 自動發布。

部署流程：

```text
push to main
→ scan job 解密並掃描敏感資訊
→ scan 成功才執行 deploy job
→ deploy job 只發布 index.html / style.css / encrypted-data.json
```

如果 scan 失敗，`deploy` job 會被 skipped，網站會停留在上一個成功部署的版本。
