# GitHub'a Yayınlama (Publishing to GitHub)

## SSH ile Projeyi Yayınlama Komutları

### 1. GitHub'da Yeni Repo Oluştur

1. [GitHub](https://github.com/new) → "New repository"
2. Repository name: `forticheck`
3. Description: `Security Analysis for FortiGate Firewalls`
4. Public seçin
5. **README, .gitignore, license eklemeyin** (zaten projede var)
6. "Create repository" tıklayın

### 2. SSH İle Push Komutları

GitHub repo sayfasında "Create repository" sonrası gösterilen komutları kullanın. SSH için:

```bash
# Remote ekle (cumakurt yerine kendi GitHub kullanıcı adınızı yazın)
git remote add origin git@github.com:cumakurt/forticheck.git

# İlk push
git push -u origin main
```

### 3. SSH Key Kontrolü

SSH key'iniz yoksa veya GitHub'a eklenmemişse:

```bash
# SSH key var mı kontrol et
ls -la ~/.ssh/id_*.pub

# Yoksa yeni key oluştur
ssh-keygen -t ed25519 -C "cumakurt@gmail.com" -f ~/.ssh/id_ed25519 -N ""

# Public key'i göster (bunu GitHub'a ekleyeceksiniz)
cat ~/.ssh/id_ed25519.pub
```

**GitHub'a SSH key ekleme:**
- GitHub → Settings → SSH and GPG keys → New SSH key
- Key'i yapıştırın

### 4. Test Bağlantısı

```bash
ssh -T git@github.com
# "Hi cumakurt! You've successfully authenticated..." mesajı görmelisiniz
```

---

## Tam Komut Seti (Sırayla)

```bash
cd /home/yula/projelerim/forticheck

# Remote ekle
git remote add origin git@github.com:cumakurt/forticheck.git

# Push
git push -u origin main
```

---

## Sonraki Güncellemeler

```bash
git add .
git commit -m "Açıklama"
git push
```
