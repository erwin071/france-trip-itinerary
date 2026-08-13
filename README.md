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
