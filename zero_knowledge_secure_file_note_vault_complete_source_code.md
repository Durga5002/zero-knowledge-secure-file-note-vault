# Zero-Knowledge Secure File & Note Vault — Complete Java Source Code

## Project Directory Structure

```text
ZeroKnowledgeVault/
└── src/
    ├── model/
    │   ├── UserAccount.java
    │   └── VaultItem.java
    ├── service/
    │   ├── CryptoProcessor.java
    │   ├── FileDecryptor.java
    │   ├── FileEncryptor.java
    │   └── VaultManager.java
    └── ui/
        └── VaultMainUI.java
```

---

## 1. Domain Model Layer (`package model`)

### 1.1 `src/model/UserAccount.java`

```java
package model;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Serializable domain model representing a vault user account.
 * Stores salted SHA-256 hashes for login authentication and security-question recovery,
 * as well as a dedicated 16-byte cryptographic salt for PBKDF2 key derivation.
 */
public class UserAccount implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String username;
    private String loginPasswordHash;
    private byte[] loginSalt;

    private String securityQuestion;
    private String securityAnswerHash;
    private byte[] recoverySalt;

    private final byte[] cryptoSalt;
    private final long createdAtMillis;

    public UserAccount(String username,
                       char[] loginPassword,
                       String securityQuestion,
                       String securityAnswer) throws Exception {
        this.username = username;
        this.createdAtMillis = System.currentTimeMillis();

        SecureRandom random = new SecureRandom();
        this.loginSalt = new byte[16];
        random.nextBytes(this.loginSalt);
        this.loginPasswordHash = hashSecret(new String(loginPassword), this.loginSalt);

        this.securityQuestion = securityQuestion;
        this.recoverySalt = new byte[16];
        random.nextBytes(this.recoverySalt);
        this.securityAnswerHash = hashSecret(securityAnswer.trim().toLowerCase(), this.recoverySalt);

        this.cryptoSalt = new byte[16];
        random.nextBytes(this.cryptoSalt);
    }

    public String getUsername() {
        return username;
    }

    public String getSecurityQuestion() {
        return securityQuestion;
    }

    public byte[] getCryptoSalt() {
        return cryptoSalt.clone();
    }

    public long getCreatedAtMillis() {
        return createdAtMillis;
    }

    public boolean verifyLoginPassword(char[] candidatePassword) {
        try {
            String candidateHash = hashSecret(new String(candidatePassword), this.loginSalt);
            return MessageDigest.isEqual(
                    candidateHash.getBytes(StandardCharsets.UTF_8),
                    this.loginPasswordHash.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }

    public boolean verifySecurityAnswer(String candidateAnswer) {
        if (candidateAnswer == null) {
            return false;
        }
        try {
            String candidateHash = hashSecret(candidateAnswer.trim().toLowerCase(), this.recoverySalt);
            return MessageDigest.isEqual(
                    candidateHash.getBytes(StandardCharsets.UTF_8),
                    this.securityAnswerHash.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }

    public void resetLoginPassword(char[] newLoginPassword) throws Exception {
        SecureRandom random = new SecureRandom();
        this.loginSalt = new byte[16];
        random.nextBytes(this.loginSalt);
        this.loginPasswordHash = hashSecret(new String(newLoginPassword), this.loginSalt);
    }

    private static String hashSecret(String secret, byte[] salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt);
        byte[] hashed = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashed);
    }
}
```

---

### 1.2 `src/model/VaultItem.java`

```java
package model;

import java.io.Serializable;

/**
 * Serializable domain model representing an encrypted file, encrypted note,
 * or virtual directory folder inside the Zero-Knowledge Vault.
 */
public class VaultItem implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum ItemType {
        FILE,
        NOTE,
        FOLDER
    }

    private final String id;
    private final String ownerUsername;
    private final ItemType type;
    private String name;
    private String parentFolderId;
    private String wrappedDekBase64;
    private String saltBase64;
    private long sizeBytes;
    private long createdAtMillis;

    public VaultItem(String id,
                     String ownerUsername,
                     ItemType type,
                     String name,
                     String parentFolderId) {
        this.id = id;
        this.ownerUsername = ownerUsername;
        this.type = type;
        this.name = name;
        this.parentFolderId = parentFolderId;
        this.createdAtMillis = System.currentTimeMillis();
    }

    public String getId() {
        return id;
    }

    public String getOwnerUsername() {
        return ownerUsername;
    }

    public ItemType getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getParentFolderId() {
        return parentFolderId;
    }

    public void setParentFolderId(String parentFolderId) {
        this.parentFolderId = parentFolderId;
    }

    public String getWrappedDekBase64() {
        return wrappedDekBase64;
    }

    public void setWrappedDekBase64(String wrappedDekBase64) {
        this.wrappedDekBase64 = wrappedDekBase64;
    }

    public String getSaltBase64() {
        return saltBase64;
    }

    public void setSaltBase64(String saltBase64) {
        this.saltBase64 = saltBase64;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public long getCreatedAtMillis() {
        return createdAtMillis;
    }

    public void setCreatedAtMillis(long createdAtMillis) {
        this.createdAtMillis = createdAtMillis;
    }
}
```

---

## 2. Service & Cryptographic Engine Layer (`package service`)

### 2.1 `src/service/CryptoProcessor.java`

```java
package service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Abstract base class defining cryptographic primitives for the Zero-Knowledge Vault:
 * - PBKDF2WithHmacSHA256 (65,536 iterations, 256-bit Master KEK)
 * - Per-item 256-bit AES Data Encryption Key (DEK) generation
 * - AES Key-Wrap / Unwrap operations
 */
public abstract class CryptoProcessor {
    protected static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
    protected static final String WRAP_ALGO = "AESWrap";
    protected static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    protected static final int ITERATIONS = 65536;
    protected static final int KEY_BITS = 256;
    protected static final int IV_BYTES = 16;
    protected static final int BUFFER_SIZE = 8192;

    /**
     * Derives a 256-bit Master Key Encryption Key (KEK) from the user's Crypto Password and salt.
     */
    public SecretKey deriveMasterKey(char[] cryptoPassword, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(cryptoPassword, salt, ITERATIONS, KEY_BITS);
        byte[] keyBytes = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGO);
            keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    /**
     * Generates a fresh cryptographically strong 256-bit AES Data Encryption Key (DEK).
     */
    public SecretKey generateDEK() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_BITS, new SecureRandom());
        return keyGen.generateKey();
    }

    /**
     * Wraps a per-item DEK under the user's derived 256-bit Master Key using RFC 3394 AES Key Wrap.
     */
    public String wrapDEK(SecretKey dek, SecretKey masterKey) throws Exception {
        Cipher wrapCipher = Cipher.getInstance(WRAP_ALGO);
        wrapCipher.init(Cipher.WRAP_MODE, masterKey);
        byte[] wrappedBytes = wrapCipher.wrap(dek);
        return Base64.getEncoder().encodeToString(wrappedBytes);
    }

    /**
     * Unwraps a stored Base64-encoded DEK using the user's derived 256-bit Master Key.
     */
    public SecretKey unwrapDEK(String wrappedDekBase64, SecretKey masterKey) throws Exception {
        byte[] wrappedBytes = Base64.getDecoder().decode(wrappedDekBase64);
        Cipher unwrapCipher = Cipher.getInstance(WRAP_ALGO);
        unwrapCipher.init(Cipher.UNWRAP_MODE, masterKey);
        return (SecretKey) unwrapCipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);
    }
}
```

---

### 2.2 `src/service/FileEncryptor.java`

```java
package service;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Buffered streaming encryptor subclassing CryptoProcessor.
 * Prepends a unique 16-byte random IV followed by AES-256-CBC ciphertext.
 */
public class FileEncryptor extends CryptoProcessor {

    /**
     * Encrypts a source file into an encrypted vault blob using an 8 KB buffer.
     */
    public void encryptFile(File inputFile, File outputFile, SecretKey dek) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            encryptStream(fis, outputFile, dek);
        }
    }

    /**
     * Encrypts UTF-8 note text into an encrypted vault blob.
     */
    public void encryptTextNote(String plainText, File outputFile, SecretKey dek) throws Exception {
        byte[] noteBytes = plainText.getBytes(StandardCharsets.UTF_8);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(noteBytes)) {
            encryptStream(bais, outputFile, dek);
        }
    }

    private void encryptStream(InputStream in, File outputFile, SecretKey dek) throws Exception {
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, dek, new IvParameterSpec(iv));

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            // Write 16-byte random IV header first
            fos.write(iv);
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
                cos.flush();
            }
        }
    }
}
```

---

### 2.3 `src/service/FileDecryptor.java`

```java
package service;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Buffered streaming decryptor subclassing CryptoProcessor.
 * Reads the 16-byte IV header and streams AES-256-CBC plaintext blocks.
 */
public class FileDecryptor extends CryptoProcessor {

    /**
     * Decrypts an encrypted vault blob to a target destination file using an 8 KB buffer.
     */
    public void decryptFile(File encryptedFile, File destinationFile, SecretKey dek) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(destinationFile)) {
            decryptToStream(encryptedFile, fos, dek);
        }
    }

    /**
     * Decrypts an encrypted note blob directly into a UTF-8 String in memory.
     */
    public String decryptTextNote(File encryptedFile, SecretKey dek) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            decryptToStream(encryptedFile, baos, dek);
            return baos.toString(StandardCharsets.UTF_8);
        }
    }

    private void decryptToStream(File encryptedFile, OutputStream out, SecretKey dek) throws Exception {
        try (FileInputStream fis = new FileInputStream(encryptedFile)) {
            byte[] iv = new byte[IV_BYTES];
            int totalRead = 0;
            while (totalRead < IV_BYTES) {
                int r = fis.read(iv, totalRead, IV_BYTES - totalRead);
                if (r == -1) {
                    throw new EOFException("Corrupted encrypted file: incomplete IV header.");
                }
                totalRead += r;
            }

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, dek, new IvParameterSpec(iv));

            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                out.flush();
            }
        }
    }
}
```

---

### 2.4 `src/service/VaultManager.java`

```java
package service;

import model.UserAccount;
import model.VaultItem;
import model.VaultItem.ItemType;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Central orchestration service for authentication, envelope encryption,
 * virtual directory management, zero-byte file sanitation, and security audit logging.
 */
public class VaultManager {
    private static final String STORAGE_DIR = "vault_storage";
    private static final String METADATA_FILE = "metadata.dat";
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final FileEncryptor encryptor = new FileEncryptor();
    private final FileDecryptor decryptor = new FileDecryptor();

    private VaultState state;
    private UserAccount activeUser;

    private static class VaultState implements Serializable {
        private static final long serialVersionUID = 1L;
        Map<String, UserAccount> users = new HashMap<>();
        List<VaultItem> items = new ArrayList<>();
        List<AuditEntry> auditLogs = new ArrayList<>();
    }

    public static class AuditEntry implements Serializable {
        private static final long serialVersionUID = 1L;
        public final String timestamp;
        public final String actor;
        public final String event;

        public AuditEntry(String timestamp, String actor, String event) {
            this.timestamp = timestamp;
            this.actor = actor;
            this.event = event;
        }
    }

    public VaultManager() {
        File dir = new File(STORAGE_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        loadMetadata();
        logEvent("SYSTEM", "Application initialized successfully.");
    }

    // ==================== Authentication & Account Recovery ====================

    public synchronized void registerUser(String username,
                                          char[] loginPassword,
                                          char[] cryptoPassword,
                                          String securityQuestion,
                                          String securityAnswer) throws Exception {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        String cleanUser = username.trim();
        if (state.users.containsKey(cleanUser)) {
            throw new IllegalArgumentException("Username already exists.");
        }
        if (loginPassword.length < 4 || cryptoPassword.length < 4) {
            throw new IllegalArgumentException("Passwords must be at least 4 characters long.");
        }

        UserAccount account = new UserAccount(cleanUser, loginPassword, securityQuestion, securityAnswer);
        state.users.put(cleanUser, account);
        logEvent(cleanUser, "ACCOUNT_REGISTERED: User account created.");
        saveMetadata();
    }

    public synchronized boolean authenticate(String username, char[] loginPassword) {
        UserAccount account = state.users.get(username.trim());
        if (account != null && account.verifyLoginPassword(loginPassword)) {
            this.activeUser = account;
            logEvent(account.getUsername(), "AUTHENTICATION_SUCCESS: Logged into vault.");
            saveMetadata();
            return true;
        }
        logEvent(username.trim(), "AUTHENTICATION_FAILED: Invalid login credentials.");
        saveMetadata();
        return false;
    }

    public synchronized String getSecurityQuestionForUser(String username) {
        UserAccount account = state.users.get(username.trim());
        return account != null ? account.getSecurityQuestion() : null;
    }

    public synchronized boolean resetLoginPassword(String username,
                                                   String securityAnswer,
                                                   char[] newLoginPassword) throws Exception {
        UserAccount account = state.users.get(username.trim());
        if (account == null) {
            return false;
        }
        if (account.verifySecurityAnswer(securityAnswer)) {
            account.resetLoginPassword(newLoginPassword);
            logEvent(account.getUsername(), "PASSWORD_RESET: Login password reset via security question.");
            saveMetadata();
            return true;
        }
        logEvent(account.getUsername(), "PASSWORD_RESET_FAILED: Incorrect security answer.");
        saveMetadata();
        return false;
    }

    public synchronized void logout(String reason) {
        if (activeUser != null) {
            logEvent(activeUser.getUsername(), "SESSION_LOCKED: " + reason);
            saveMetadata();
            activeUser = null;
        }
    }

    public UserAccount getActiveUser() {
        return activeUser;
    }

    // ==================== Virtual Directory & Item Operations ====================

    public synchronized VaultItem createFolder(String folderName, String parentFolderId) {
        ensureAuthenticated();
        String uuid = UUID.randomUUID().toString();
        VaultItem folder = new VaultItem(uuid, activeUser.getUsername(), ItemType.FOLDER, folderName, parentFolderId);
        folder.setSizeBytes(0L);
        state.items.add(folder);
        logEvent(activeUser.getUsername(), "FOLDER_CREATED: '" + folderName + "' (ID: " + uuid + ")");
        saveMetadata();
        return folder;
    }

    public synchronized VaultItem importFile(File sourceFile,
                                             String parentFolderId,
                                             char[] cryptoPassword,
                                             boolean moveAndWipe) throws Exception {
        ensureAuthenticated();
        SecretKey masterKey = encryptor.deriveMasterKey(cryptoPassword, activeUser.getCryptoSalt());
        Arrays.fill(cryptoPassword, '\0');

        SecretKey dek = encryptor.generateDEK();
        String wrappedDek = encryptor.wrapDEK(dek, masterKey);

        String uuid = UUID.randomUUID().toString();
        File encryptedBlob = new File(STORAGE_DIR, uuid + ".enc");
        encryptor.encryptFile(sourceFile, encryptedBlob, dek);

        VaultItem item = new VaultItem(uuid, activeUser.getUsername(), ItemType.FILE, sourceFile.getName(), parentFolderId);
        item.setWrappedDekBase64(wrappedDek);
        item.setSaltBase64(Base64.getEncoder().encodeToString(activeUser.getCryptoSalt()));
        item.setSizeBytes(sourceFile.length());

        state.items.add(item);

        if (moveAndWipe) {
            secureZeroWipeFile(sourceFile);
            logEvent(activeUser.getUsername(), "FILE_MOVED_AND_WIPED: '" + sourceFile.getName() + "' -> " + uuid);
        } else {
            logEvent(activeUser.getUsername(), "FILE_ENCRYPTED: '" + sourceFile.getName() + "' -> " + uuid);
        }

        saveMetadata();
        return item;
    }

    public synchronized VaultItem createOrUpdateEncryptedNote(String existingNoteId,
                                                              String title,
                                                              String content,
                                                              String parentFolderId,
                                                              char[] cryptoPassword) throws Exception {
        ensureAuthenticated();
        SecretKey masterKey = encryptor.deriveMasterKey(cryptoPassword, activeUser.getCryptoSalt());
        Arrays.fill(cryptoPassword, '\0');

        SecretKey dek = encryptor.generateDEK();
        String wrappedDek = encryptor.wrapDEK(dek, masterKey);

        String uuid = (existingNoteId != null) ? existingNoteId : UUID.randomUUID().toString();
        File encryptedBlob = new File(STORAGE_DIR, uuid + ".enc");
        encryptor.encryptTextNote(content, encryptedBlob, dek);

        VaultItem existing = findItemById(uuid);
        if (existing != null) {
            existing.setName(title);
            existing.setWrappedDekBase64(wrappedDek);
            existing.setSizeBytes(content.getBytes(StandardCharsets.UTF_8).length);
            logEvent(activeUser.getUsername(), "NOTE_UPDATED: '" + title + "' (" + uuid + ")");
            saveMetadata();
            return existing;
        } else {
            VaultItem noteItem = new VaultItem(uuid, activeUser.getUsername(), ItemType.NOTE, title, parentFolderId);
            noteItem.setWrappedDekBase64(wrappedDek);
            noteItem.setSaltBase64(Base64.getEncoder().encodeToString(activeUser.getCryptoSalt()));
            noteItem.setSizeBytes(content.getBytes(StandardCharsets.UTF_8).length);
            state.items.add(noteItem);
            logEvent(activeUser.getUsername(), "NOTE_CREATED: '" + title + "' (" + uuid + ")");
            saveMetadata();
            return noteItem;
        }
    }

    public synchronized void decryptAndExportFile(VaultItem item,
                                                  File destinationFile,
                                                  char[] cryptoPassword) throws Exception {
        ensureAuthenticated();
        SecretKey masterKey = decryptor.deriveMasterKey(cryptoPassword, activeUser.getCryptoSalt());
        Arrays.fill(cryptoPassword, '\0');

        SecretKey dek = decryptor.unwrapDEK(item.getWrappedDekBase64(), masterKey);
        File encryptedBlob = new File(STORAGE_DIR, item.getId() + ".enc");
        decryptor.decryptFile(encryptedBlob, destinationFile, dek);

        logEvent(activeUser.getUsername(), "FILE_DECRYPTED_EXPORTED: '" + item.getName() + "' -> " + destinationFile.getName());
        saveMetadata();
    }

    public synchronized String decryptNoteContent(VaultItem item, char[] cryptoPassword) throws Exception {
        ensureAuthenticated();
        SecretKey masterKey = decryptor.deriveMasterKey(cryptoPassword, activeUser.getCryptoSalt());
        Arrays.fill(cryptoPassword, '\0');

        SecretKey dek = decryptor.unwrapDEK(item.getWrappedDekBase64(), masterKey);
        File encryptedBlob = new File(STORAGE_DIR, item.getId() + ".enc");
        String plaintext = decryptor.decryptTextNote(encryptedBlob, dek);

        logEvent(activeUser.getUsername(), "NOTE_DECRYPTED_VIEWED: '" + item.getName() + "'");
        saveMetadata();
        return plaintext;
    }

    public synchronized void moveItemToFolder(String itemId, String targetFolderId) {
        ensureAuthenticated();
        VaultItem item = findItemById(itemId);
        if (item != null && !item.getId().equals(targetFolderId)) {
            item.setParentFolderId(targetFolderId);
            logEvent(activeUser.getUsername(), "ITEM_MOVED: '" + item.getName() + "' -> Folder " +
                    (targetFolderId == null ? "Root" : targetFolderId));
            saveMetadata();
        }
    }

    public synchronized void deleteItemSecurely(String itemId) throws Exception {
        ensureAuthenticated();
        VaultItem target = findItemById(itemId);
        if (target == null) {
            return;
        }

        if (target.getType() == ItemType.FOLDER) {
            List<VaultItem> children = getItemsInFolder(target.getId());
            for (VaultItem child : children) {
                deleteItemSecurely(child.getId());
            }
        } else {
            File blob = new File(STORAGE_DIR, target.getId() + ".enc");
            if (blob.exists()) {
                secureZeroWipeFile(blob);
            }
        }

        state.items.remove(target);
        logEvent(activeUser.getUsername(), "ITEM_WIPED_DELETED: '" + target.getName() + "' (" + target.getId() + ")");
        saveMetadata();
    }

    /**
     * Overwrites every byte of targetFile with 0x00 and forces OS disk sync before deletion.
     */
    public void secureZeroWipeFile(File targetFile) throws Exception {
        if (targetFile == null || !targetFile.exists() || !targetFile.isFile()) {
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(targetFile, "rw")) {
            byte[] zeros = new byte[4096];
            long remaining = raf.length();
            while (remaining > 0) {
                int chunk = (int) Math.min(zeros.length, remaining);
                raf.write(zeros, 0, chunk);
                remaining -= chunk;
            }
            raf.getFD().sync();
        }
        Files.deleteIfExists(targetFile.toPath());
    }

    // ==================== Queries & Audit Export ====================

    public synchronized List<VaultItem> getItemsInFolder(String folderId) {
        List<VaultItem> result = new ArrayList<>();
        if (activeUser == null) {
            return result;
        }
        for (VaultItem item : state.items) {
            if (item.getOwnerUsername().equals(activeUser.getUsername())) {
                boolean sameParent = (folderId == null && item.getParentFolderId() == null)
                        || (folderId != null && folderId.equals(item.getParentFolderId()));
                if (sameParent) {
                    result.add(item);
                }
            }
        }
        return result;
    }

    public synchronized List<VaultItem> getAllFoldersForActiveUser() {
        List<VaultItem> folders = new ArrayList<>();
        if (activeUser == null) {
            return folders;
        }
        for (VaultItem item : state.items) {
            if (item.getOwnerUsername().equals(activeUser.getUsername()) && item.getType() == ItemType.FOLDER) {
                folders.add(item);
            }
        }
        return folders;
    }

    public synchronized VaultItem findItemById(String id) {
        if (id == null) {
            return null;
        }
        for (VaultItem item : state.items) {
            if (item.getId().equals(id)) {
                return item;
            }
        }
        return null;
    }

    public synchronized List<AuditEntry> getAuditLogs() {
        return new ArrayList<>(state.auditLogs);
    }

    public synchronized void exportAuditLogsToCsv(File csvFile) throws Exception {
        try (PrintWriter writer = new PrintWriter(new FileWriter(csvFile, StandardCharsets.UTF_8))) {
            writer.println("Timestamp,User/System,SecurityEvent");
            for (AuditEntry entry : state.auditLogs) {
                String safeEvent = "\"" + entry.event.replace("\"", "\"\"") + "\"";
                writer.println(entry.timestamp + "," + entry.actor + "," + safeEvent);
            }
        }
        if (activeUser != null) {
            logEvent(activeUser.getUsername(), "AUDIT_CSV_EXPORTED: " + csvFile.getName());
            saveMetadata();
        }
    }

    private void logEvent(String actor, String description) {
        String ts = LocalDateTime.now().format(TS_FMT);
        state.auditLogs.add(new AuditEntry(ts, actor, description));
    }

    private void ensureAuthenticated() {
        if (activeUser == null) {
            throw new IllegalStateException("Vault session is locked or unauthenticated.");
        }
    }

    private void loadMetadata() {
        File metaFile = new File(METADATA_FILE);
        if (metaFile.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(metaFile))) {
                state = (VaultState) ois.readObject();
                return;
            } catch (Exception ignored) {
            }
        }
        state = new VaultState();
    }

    private void saveMetadata() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(METADATA_FILE))) {
            oos.writeObject(state);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

## 3. Presentation Layer (`package ui`)

### 3.1 `src/ui/VaultMainUI.java`

```java
package ui;

import model.VaultItem;
import model.VaultItem.ItemType;
import service.VaultManager;
import service.VaultManager.AuditEntry;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.AWTEvent;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Dark-themed Java Swing desktop interface for the Zero-Knowledge Secure File & Note Vault.
 * Features dual-password registration/recovery, virtual folder breadcrumbs, live search/filtering,
 * cryptographic metadata inspector, 3-minute inactivity auto-lock, and Ctrl+L quick lock.
 */
public class VaultMainUI extends JFrame {
    // Dark Slate Palette
    private static final Color BG_PRIMARY = new Color(15, 23, 42);
    private static final Color BG_SECONDARY = new Color(30, 41, 59);
    private static final Color BG_CARD = new Color(24, 34, 52);
    private static final Color ACCENT_PRIMARY = new Color(99, 102, 241);
    private static final Color ACCENT_CYAN = new Color(14, 165, 233);
    private static final Color ACCENT_GREEN = new Color(16, 185, 129);
    private static final Color ACCENT_AMBER = new Color(217, 119, 6);
    private static final Color ACCENT_RED = new Color(225, 29, 72);
    private static final Color TEXT_LIGHT = new Color(241, 245, 249);
    private static final Color TEXT_MUTED = new Color(148, 163, 184);

    private static final int AUTO_LOCK_MS = 3 * 60 * 1000; // 3 Minutes

    private final VaultManager vaultManager;
    private final CardLayout cardLayout = new CardLayout();
    private final JPanel rootContainer = new JPanel(cardLayout);

    // Login Components
    private JTextField loginUserField;
    private JPasswordField loginPassField;
    private JProgressBar passwordStrengthBar;
    private JLabel passwordStrengthLabel;

    // Dashboard Components
    private JLabel sessionUserLabel;
    private JLabel driveSpaceLabel;
    private JProgressBar driveSpaceBar;
    private JButton backFolderBtn;
    private JLabel breadcrumbLabel;
    private JTextField searchField;
    private JComboBox<String> categoryFilterBox;

    private DefaultTableModel vaultTableModel;
    private JTable vaultTable;
    private TableRowSorter<DefaultTableModel> tableSorter;

    private DefaultTableModel auditTableModel;
    private JTable auditTable;

    // Metadata Inspector Labels
    private JLabel metaNameLabel;
    private JLabel metaTypeLabel;
    private JLabel metaSizeLabel;
    private JLabel metaCreatedLabel;
    private JLabel metaUuidLabel;

    private String currentFolderId = null;
    private Timer inactivityTimer;

    public VaultMainUI() {
        this.vaultManager = new VaultManager();

        setTitle("Zero-Knowledge Secure File & Note Vault");
        setSize(1180, 720);
        setMinimumSize(new Dimension(1020, 640));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        rootContainer.add(buildLoginView(), "LOGIN");
        rootContainer.add(buildDashboardView(), "DASHBOARD");
        add(rootContainer);

        setupSessionSecurity();
        cardLayout.show(rootContainer, "LOGIN");
    }

    // ==================== Session Security & Auto-Lock ====================

    private void setupSessionSecurity() {
        inactivityTimer = new Timer(AUTO_LOCK_MS, e -> {
            if (vaultManager.getActiveUser() != null) {
                lockVaultSession("Auto-locked due to 3 minutes of inactivity.");
            }
        });
        inactivityTimer.setRepeats(false);

        Toolkit.getDefaultToolkit().addAWTEventListener(event -> {
            if (vaultManager.getActiveUser() != null && inactivityTimer != null) {
                inactivityTimer.restart();
            }
        }, AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK | AWTEvent.KEY_EVENT_MASK);

        // Global Ctrl+L Quick Lock Shortcut
        rootContainer.getInputMap(JPanel.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_L, KeyEvent.CTRL_DOWN_MASK), "QUICK_LOCK");
        rootContainer.getActionMap().put("QUICK_LOCK", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (vaultManager.getActiveUser() != null) {
                    lockVaultSession("Quick-locked via Ctrl+L shortcut.");
                }
            }
        });
    }

    private void lockVaultSession(String reason) {
        if (inactivityTimer != null) {
            inactivityTimer.stop();
        }
        vaultManager.logout(reason);
        currentFolderId = null;
        loginPassField.setText("");
        cardLayout.show(rootContainer, "LOGIN");
        JOptionPane.showMessageDialog(this, reason, "Vault Locked", JOptionPane.INFORMATION_MESSAGE);
    }

    // ==================== Login & Registration View ====================

    private JPanel buildLoginView() {
        JPanel wrapper = new JPanel(new GridBagLayout());
        wrapper.setBackground(BG_PRIMARY);

        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(BG_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(51, 65, 85), 1),
                BorderFactory.createEmptyBorder(32, 40, 32, 40)
        ));
        card.setPreferredSize(new Dimension(430, 460));

        JLabel title = new JLabel("SECURE FILE & NOTE VAULT");
        title.setFont(new Font("SansSerif", Font.BOLD, 20));
        title.setForeground(ACCENT_PRIMARY);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitle = new JLabel("Zero-Knowledge Encrypted Storage Platform");
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        subtitle.setForeground(TEXT_MUTED);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel userLbl = new JLabel("Username");
        userLbl.setForeground(TEXT_LIGHT);
        userLbl.setFont(new Font("SansSerif", Font.BOLD, 12));
        userLbl.setAlignmentX(Component.CENTER_ALIGNMENT);

        loginUserField = new JTextField();
        styleInputField(loginUserField);

        JLabel passLbl = new JLabel("Login Password");
        passLbl.setForeground(TEXT_LIGHT);
        passLbl.setFont(new Font("SansSerif", Font.BOLD, 12));
        passLbl.setAlignmentX(Component.CENTER_ALIGNMENT);

        loginPassField = new JPasswordField();
        styleInputField(loginPassField);

        passwordStrengthBar = new JProgressBar(0, 100);
        passwordStrengthBar.setPreferredSize(new Dimension(340, 6));
        passwordStrengthBar.setMaximumSize(new Dimension(340, 6));
        passwordStrengthBar.setForeground(ACCENT_RED);

        passwordStrengthLabel = new JLabel("Password Strength: None");
        passwordStrengthLabel.setForeground(TEXT_MUTED);
        passwordStrengthLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        passwordStrengthLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        loginPassField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { updateStrengthMeter(); }
            public void removeUpdate(DocumentEvent e) { updateStrengthMeter(); }
            public void changedUpdate(DocumentEvent e) { updateStrengthMeter(); }
        });

        JButton loginBtn = createStyledButton("Login to Vault", ACCENT_PRIMARY);
        loginBtn.setMaximumSize(new Dimension(340, 38));
        loginBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        loginBtn.addActionListener(e -> handleLogin());

        JButton registerBtn = createStyledButton("Register New Account", BG_SECONDARY);
        registerBtn.setMaximumSize(new Dimension(340, 38));
        registerBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        registerBtn.addActionListener(e -> openRegistrationDialog());

        JButton forgotBtn = new JButton("Forgot Password?");
        forgotBtn.setForeground(TEXT_LIGHT);
        forgotBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        forgotBtn.setBorderPainted(false);
        forgotBtn.setContentAreaFilled(false);
        forgotBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        forgotBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        forgotBtn.addActionListener(e -> openRecoveryDialog());

        card.add(title);
        card.add(Box.createVerticalStrut(4));
        card.add(subtitle);
        card.add(Box.createVerticalStrut(24));
        card.add(userLbl);
        card.add(Box.createVerticalStrut(6));
        card.add(loginUserField);
        card.add(Box.createVerticalStrut(14));
        card.add(passLbl);
        card.add(Box.createVerticalStrut(6));
        card.add(loginPassField);
        card.add(Box.createVerticalStrut(8));
        card.add(passwordStrengthBar);
        card.add(Box.createVerticalStrut(4));
        card.add(passwordStrengthLabel);
        card.add(Box.createVerticalStrut(20));
        card.add(loginBtn);
        card.add(Box.createVerticalStrut(10));
        card.add(registerBtn);
        card.add(Box.createVerticalStrut(12));
        card.add(forgotBtn);

        wrapper.add(card);
        return wrapper;
    }

    private void updateStrengthMeter() {
        char[] pw = loginPassField.getPassword();
        int score = 0;
        if (pw.length >= 6) score += 30;
        if (pw.length >= 10) score += 25;
        String s = new String(pw);
        if (s.matches(".*[A-Z].*")) score += 15;
        if (s.matches(".*[0-9].*")) score += 15;
        if (s.matches(".*[^a-zA-Z0-9].*")) score += 15;
        Arrays.fill(pw, '\0');

        passwordStrengthBar.setValue(score);
        if (score == 0) {
            passwordStrengthLabel.setText("Password Strength: None");
            passwordStrengthBar.setForeground(ACCENT_RED);
        } else if (score < 50) {
            passwordStrengthLabel.setText("Password Strength: Weak");
            passwordStrengthBar.setForeground(ACCENT_RED);
        } else if (score < 80) {
            passwordStrengthLabel.setText("Password Strength: Moderate");
            passwordStrengthBar.setForeground(ACCENT_AMBER);
        } else {
            passwordStrengthLabel.setText("Password Strength: Strong");
            passwordStrengthBar.setForeground(ACCENT_GREEN);
        }
    }

    private void handleLogin() {
        String username = loginUserField.getText().trim();
        char[] password = loginPassField.getPassword();
        if (vaultManager.authenticate(username, password)) {
            Arrays.fill(password, '\0');
            currentFolderId = null;
            sessionUserLabel.setText("Vault Session: " + username);
            updateDriveSpaceIndicator();
            refreshVaultTable();
            refreshAuditTable();
            inactivityTimer.restart();
            cardLayout.show(rootContainer, "DASHBOARD");
        } else {
            Arrays.fill(password, '\0');
            JOptionPane.showMessageDialog(this, "Invalid username or login password.",
                    "Authentication Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void openRegistrationDialog() {
        JTextField userField = new JTextField();
        JPasswordField loginPwField = new JPasswordField();
        JPasswordField cryptoPwField = new JPasswordField();
        JTextField questionField = new JTextField();
        JTextField answerField = new JTextField();

        Object[] fields = {
                "Username:", userField,
                "Login Password:", loginPwField,
                "Crypto Password (Used strictly for file/note decryption):", cryptoPwField,
                "Security Question (For login password resets):", questionField,
                "Security Answer:", answerField
        };

        int opt = JOptionPane.showConfirmDialog(this, fields, "Register Account",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (opt == JOptionPane.OK_OPTION) {
            try {
                vaultManager.registerUser(
                        userField.getText(),
                        loginPwField.getPassword(),
                        cryptoPwField.getPassword(),
                        questionField.getText(),
                        answerField.getText()
                );
                JOptionPane.showMessageDialog(this, "Account created successfully! Please log in.",
                        "Registration Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(),
                        "Registration Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void openRecoveryDialog() {
        String username = JOptionPane.showInputDialog(this, "Enter your Username:",
                "Recover Login Password", JOptionPane.QUESTION_MESSAGE);
        if (username == null || username.trim().isEmpty()) return;

        String question = vaultManager.getSecurityQuestionForUser(username);
        if (question == null) {
            JOptionPane.showMessageDialog(this, "User account not found.",
                    "Recovery Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JTextField ansField = new JTextField();
        JPasswordField newPwField = new JPasswordField();
        Object[] msg = {
                "Security Question: " + question,
                "Security Answer:", ansField,
                "New Login Password:", newPwField
        };

        int res = JOptionPane.showConfirmDialog(this, msg, "Reset Login Password",
                JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            try {
                boolean ok = vaultManager.resetLoginPassword(username, ansField.getText(), newPwField.getPassword());
                if (ok) {
                    JOptionPane.showMessageDialog(this, "Login password updated successfully.",
                            "Password Reset", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, "Incorrect security answer.",
                            "Verification Failed", JOptionPane.ERROR_MESSAGE);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ==================== Main Vault Dashboard View ====================

    private JPanel buildDashboardView() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBackground(BG_PRIMARY);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        // Top Header Bar
        JPanel topHeader = new JPanel(new BorderLayout());
        topHeader.setBackground(BG_PRIMARY);

        JPanel leftHeader = new JPanel();
        leftHeader.setLayout(new BoxLayout(leftHeader, BoxLayout.Y_AXIS));
        leftHeader.setBackground(BG_PRIMARY);

        sessionUserLabel = new JLabel("Vault Session: -");
        sessionUserLabel.setFont(new Font("SansSerif", Font.BOLD, 18));
        sessionUserLabel.setForeground(TEXT_LIGHT);

        driveSpaceLabel = new JLabel("Drive Storage: Calculating...");
        driveSpaceLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        driveSpaceLabel.setForeground(TEXT_MUTED);

        driveSpaceBar = new JProgressBar(0, 100);
        driveSpaceBar.setPreferredSize(new Dimension(280, 7));
        driveSpaceBar.setMaximumSize(new Dimension(280, 7));
        driveSpaceBar.setForeground(ACCENT_PRIMARY);
        driveSpaceBar.setBackground(BG_SECONDARY);

        leftHeader.add(sessionUserLabel);
        leftHeader.add(Box.createVerticalStrut(4));
        leftHeader.add(driveSpaceLabel);
        leftHeader.add(Box.createVerticalStrut(4));
        leftHeader.add(driveSpaceBar);

        JPanel rightHeader = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 4));
        rightHeader.setBackground(BG_PRIMARY);

        JButton quickLockBtn = createStyledButton("Quick Lock (Ctrl+L)", ACCENT_AMBER);
        quickLockBtn.addActionListener(e -> lockVaultSession("Quick-locked by user."));

        JButton logoutBtn = createStyledButton("Logout", ACCENT_RED);
        logoutBtn.addActionListener(e -> lockVaultSession("User logged out."));

        rightHeader.add(quickLockBtn);
        rightHeader.add(logoutBtn);

        topHeader.add(leftHeader, BorderLayout.WEST);
        topHeader.add(rightHeader, BorderLayout.EAST);
        mainPanel.add(topHeader, BorderLayout.NORTH);

        // Center Tabbed Workspace
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Encrypted Storage", buildStorageTab());
        tabbedPane.addTab("Security Audit Logs", buildAuditTab());
        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        // Bottom Action Toolbar
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 6));
        bottomBar.setBackground(BG_PRIMARY);

        JButton newFolderBtn = createStyledButton("+ New Folder", ACCENT_PRIMARY);
        newFolderBtn.addActionListener(e -> handleCreateFolder());

        JButton uploadBtn = createStyledButton("Upload File", new Color(79, 70, 229));
        uploadBtn.addActionListener(e -> handleUploadFile());

        JButton secureNoteBtn = createStyledButton("+ Secure Note", ACCENT_CYAN);
        secureNoteBtn.addActionListener(e -> handleCreateOrEditNote(null));

        JButton moveBtn = createStyledButton("Move to Folder", ACCENT_PRIMARY);
        moveBtn.addActionListener(e -> handleMoveToFolder());

        JButton openBtn = createStyledButton("Open / Restore", ACCENT_GREEN);
        openBtn.addActionListener(e -> handleOpenOrRestore());

        JButton deleteBtn = createStyledButton("Delete Item", ACCENT_RED);
        deleteBtn.addActionListener(e -> handleDeleteItem());

        JButton exportCsvBtn = createStyledButton("Export Audit CSV", new Color(71, 85, 105));
        exportCsvBtn.addActionListener(e -> handleExportCsv());

        bottomBar.add(newFolderBtn);
        bottomBar.add(uploadBtn);
        bottomBar.add(secureNoteBtn);
        bottomBar.add(moveBtn);
        bottomBar.add(openBtn);
        bottomBar.add(deleteBtn);
        bottomBar.add(exportCsvBtn);

        mainPanel.add(bottomBar, BorderLayout.SOUTH);
        return mainPanel;
    }

    private JPanel buildStorageTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 8));
        panel.setBackground(new Color(203, 213, 225));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Navigation & Search Strip
        JPanel navBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        navBar.setBackground(new Color(203, 213, 225));

        backFolderBtn = createStyledButton("< Back Folder", new Color(71, 85, 105));
        backFolderBtn.setEnabled(false);
        backFolderBtn.addActionListener(e -> navigateUpFolder());

        breadcrumbLabel = new JLabel("Location: Root");
        breadcrumbLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        breadcrumbLabel.setForeground(new Color(51, 65, 85));

        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setForeground(new Color(51, 65, 85));

        searchField = new JTextField(18);
        searchField.setBackground(BG_PRIMARY);
        searchField.setForeground(TEXT_LIGHT);
        searchField.setCaretColor(TEXT_LIGHT);

        JLabel catLbl = new JLabel("Category:");
        catLbl.setForeground(new Color(51, 65, 85));

        categoryFilterBox = new JComboBox<>(new String[]{"All Items", "FILE", "NOTE", "FOLDER"});
        categoryFilterBox.addActionListener(e -> applyTableFilters());

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyTableFilters(); }
            public void removeUpdate(DocumentEvent e) { applyTableFilters(); }
            public void changedUpdate(DocumentEvent e) { applyTableFilters(); }
        });

        navBar.add(backFolderBtn);
        navBar.add(breadcrumbLabel);
        navBar.add(searchLbl);
        navBar.add(searchField);
        navBar.add(catLbl);
        navBar.add(categoryFilterBox);

        panel.add(navBar, BorderLayout.NORTH);

        // Center Item Table
        String[] cols = {"Type", "File/Note UUID", "Name / Title", "Size (Bytes)", "Created Date"};
        vaultTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        vaultTable = new JTable(vaultTableModel);
        vaultTable.setBackground(BG_PRIMARY);
        vaultTable.setForeground(TEXT_LIGHT);
        vaultTable.setSelectionBackground(ACCENT_PRIMARY);
        vaultTable.setSelectionForeground(Color.WHITE);
        vaultTable.setRowHeight(28);
        vaultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        vaultTable.getTableHeader().setBackground(BG_SECONDARY);
        vaultTable.getTableHeader().setForeground(TEXT_LIGHT);
        vaultTable.getTableHeader().setFont(new Font("SansSerif", Font.BOLD, 12));

        tableSorter = new TableRowSorter<>(vaultTableModel);
        vaultTable.setRowSorter(tableSorter);

        vaultTable.getSelectionModel().addListSelectionListener(e -> updateMetadataInspector());
        vaultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    handleOpenOrRestore();
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(vaultTable);
        tableScroll.getViewport().setBackground(BG_PRIMARY);
        panel.add(tableScroll, BorderLayout.CENTER);

        // Right Cryptographic Metadata Sidebar
        JPanel metaPanel = new JPanel();
        metaPanel.setLayout(new BoxLayout(metaPanel, BoxLayout.Y_AXIS));
        metaPanel.setBackground(BG_CARD);
        metaPanel.setPreferredSize(new Dimension(245, 0));
        metaPanel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        JLabel metaHeader = new JLabel("CRYPTOGRAPHIC METADATA");
        metaHeader.setFont(new Font("SansSerif", Font.BOLD, 12));
        metaHeader.setForeground(ACCENT_PRIMARY);

        metaNameLabel = createMetaLabel("Name: -");
        metaTypeLabel = createMetaLabel("Type: -");
        metaSizeLabel = createMetaLabel("Size: -");
        metaCreatedLabel = createMetaLabel("Created: -");
        JLabel metaCipherLabel = createMetaLabel("Cipher: AES-256-CBC");
        metaUuidLabel = createMetaLabel("UUID: -");

        metaPanel.add(metaHeader);
        metaPanel.add(Box.createVerticalStrut(12));
        metaPanel.add(metaNameLabel);
        metaPanel.add(Box.createVerticalStrut(8));
        metaPanel.add(metaTypeLabel);
        metaPanel.add(Box.createVerticalStrut(8));
        metaPanel.add(metaSizeLabel);
        metaPanel.add(Box.createVerticalStrut(8));
        metaPanel.add(metaCreatedLabel);
        metaPanel.add(Box.createVerticalStrut(8));
        metaPanel.add(metaCipherLabel);
        metaPanel.add(Box.createVerticalStrut(8));
        metaPanel.add(metaUuidLabel);

        panel.add(metaPanel, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildAuditTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_PRIMARY);

        String[] cols = {"Timestamp", "User / System", "Security Event"};
        auditTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        auditTable = new JTable(auditTableModel);
        auditTable.setBackground(BG_PRIMARY);
        auditTable.setForeground(TEXT_LIGHT);
        auditTable.setRowHeight(26);
        auditTable.getTableHeader().setBackground(BG_SECONDARY);
        auditTable.getTableHeader().setForeground(TEXT_LIGHT);
        auditTable.getTableHeader().setFont(new Font("SansSerif", Font.BOLD, 12));

        JScrollPane scroll = new JScrollPane(auditTable);
        scroll.getViewport().setBackground(BG_PRIMARY);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    // ==================== Vault Actions ====================

    private void handleCreateFolder() {
        String name = JOptionPane.showInputDialog(this, "Enter Virtual Folder Name:",
                "New Folder", JOptionPane.PLAIN_MESSAGE);
        if (name != null && !name.trim().isEmpty()) {
            vaultManager.createFolder(name.trim(), currentFolderId);
            refreshVaultTable();
            refreshAuditTable();
        }
    }

    private void handleUploadFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File selectedFile = chooser.getSelectedFile();

        String[] modes = {"Copy & Encrypt (Keep Original)", "Move & Wipe (Zero-Byte Overwrite Original)"};
        int modeChoice = JOptionPane.showOptionDialog(this,
                "Choose file import mode for '" + selectedFile.getName() + "':",
                "Import Mode", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, modes, modes[0]);
        if (modeChoice < 0) return;

        char[] cryptoPw = promptCryptoPassword("Enter Crypto Password to wrap file DEK:");
        if (cryptoPw == null) return;

        try {
            vaultManager.importFile(selectedFile, currentFolderId, cryptoPw, modeChoice == 1);
            updateDriveSpaceIndicator();
            refreshVaultTable();
            refreshAuditTable();
            JOptionPane.showMessageDialog(this, "File encrypted and stored securely.",
                    "Upload Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Encryption failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleCreateOrEditNote(VaultItem existingNote) {
        JDialog dialog = new JDialog(this,
                existingNote == null ? "New Encrypted Note" : "View / Edit Encrypted Note", true);
        dialog.setSize(520, 420);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(10, 10));

        JTextField titleField = new JTextField(existingNote != null ? existingNote.getName() : "");
        JTextArea bodyArea = new JTextArea();
        bodyArea.setLineWrap(true);
        bodyArea.setWrapStyleWord(true);

        if (existingNote != null) {
            char[] cryptoPw = promptCryptoPassword("Enter Crypto Password to decrypt note:");
            if (cryptoPw == null) return;
            try {
                bodyArea.setText(vaultManager.decryptNoteContent(existingNote, cryptoPw));
                refreshAuditTable();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Decryption failed. Invalid Crypto Password.",
                        "Access Denied", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }

        JPanel top = new JPanel(new BorderLayout(6, 6));
        top.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
        top.add(new JLabel("Note Title:"), BorderLayout.WEST);
        top.add(titleField, BorderLayout.CENTER);

        JScrollPane centerScroll = new JScrollPane(bodyArea);
        centerScroll.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));

        JButton saveBtn = createStyledButton("Encrypt & Save Note", ACCENT_CYAN);
        saveBtn.addActionListener(e -> {
            String title = titleField.getText().trim();
            if (title.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Note title cannot be empty.");
                return;
            }
            char[] cryptoPw = promptCryptoPassword("Enter Crypto Password to encrypt note:");
            if (cryptoPw == null) return;
            try {
                vaultManager.createOrUpdateEncryptedNote(
                        existingNote != null ? existingNote.getId() : null,
                        title,
                        bodyArea.getText(),
                        currentFolderId,
                        cryptoPw
                );
                refreshVaultTable();
                refreshAuditTable();
                dialog.dispose();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "Save failed: " + ex.getMessage());
            }
        });

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottom.add(saveBtn);

        dialog.add(top, BorderLayout.NORTH);
        dialog.add(centerScroll, BorderLayout.CENTER);
        dialog.add(bottom, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private void handleMoveToFolder() {
        VaultItem selected = getSelectedVaultItem();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Select an item to move.");
            return;
        }

        List<VaultItem> folders = vaultManager.getAllFoldersForActiveUser();
        List<String> labels = new ArrayList<>();
        List<String> ids = new ArrayList<>();

        labels.add("Root Directory");
        ids.add(null);

        for (VaultItem f : folders) {
            if (!f.getId().equals(selected.getId())) {
                labels.add(f.getName() + " (" + f.getId().substring(0, 8) + ")");
                ids.add(f.getId());
            }
        }

        String choice = (String) JOptionPane.showInputDialog(this,
                "Move '" + selected.getName() + "' to:",
                "Move to Folder", JOptionPane.PLAIN_MESSAGE, null,
                labels.toArray(new String[0]), labels.get(0));
        if (choice != null) {
            int idx = labels.indexOf(choice);
            vaultManager.moveItemToFolder(selected.getId(), ids.get(idx));
            refreshVaultTable();
            refreshAuditTable();
        }
    }

    private void handleOpenOrRestore() {
        VaultItem selected = getSelectedVaultItem();
        if (selected == null) return;

        if (selected.getType() == ItemType.FOLDER) {
            currentFolderId = selected.getId();
            refreshVaultTable();
        } else if (selected.getType() == ItemType.NOTE) {
            handleCreateOrEditNote(selected);
        } else {
            JFileChooser saver = new JFileChooser();
            saver.setSelectedFile(new File(selected.getName()));
            if (saver.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

            char[] cryptoPw = promptCryptoPassword("Enter Crypto Password to decrypt file:");
            if (cryptoPw == null) return;

            try {
                vaultManager.decryptAndExportFile(selected, saver.getSelectedFile(), cryptoPw);
                refreshAuditTable();
                JOptionPane.showMessageDialog(this, "File decrypted and restored successfully.",
                        "Decryption Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Decryption failed. Verify your Crypto Password.",
                        "Access Denied", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void handleDeleteItem() {
        VaultItem selected = getSelectedVaultItem();
        if (selected == null) return;

        int confirm = JOptionPane.showConfirmDialog(this,
                "Permanently zero-wipe and delete '" + selected.getName() + "'?",
                "Confirm Secure Wipe", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            try {
                vaultManager.deleteItemSecurely(selected.getId());
                updateDriveSpaceIndicator();
                refreshVaultTable();
                refreshAuditTable();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error deleting item: " + ex.getMessage());
            }
        }
    }

    private void handleExportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("vault_audit_report.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                vaultManager.exportAuditLogsToCsv(chooser.getSelectedFile());
                refreshAuditTable();
                JOptionPane.showMessageDialog(this, "Security audit log exported to CSV.",
                        "Export Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage());
            }
        }
    }

    // ==================== Table Refresh & UI Helpers ====================

    private void refreshVaultTable() {
        vaultTableModel.setRowCount(0);
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm");

        for (VaultItem item : vaultManager.getItemsInFolder(currentFolderId)) {
            vaultTableModel.addRow(new Object[]{
                    "[" + item.getType().name() + "]",
                    item.getId(),
                    item.getName(),
                    item.getType() == ItemType.FOLDER ? "-" : item.getSizeBytes(),
                    df.format(new Date(item.getCreatedAtMillis()))
            });
        }

        updateBreadcrumbPath();
        updateMetadataInspector();
    }

    private void refreshAuditTable() {
        auditTableModel.setRowCount(0);
        for (AuditEntry entry : vaultManager.getAuditLogs()) {
            auditTableModel.addRow(new Object[]{entry.timestamp, entry.actor, entry.event});
        }
    }

    private void navigateUpFolder() {
        if (currentFolderId != null) {
            VaultItem current = vaultManager.findItemById(currentFolderId);
            currentFolderId = (current != null) ? current.getParentFolderId() : null;
            refreshVaultTable();
        }
    }

    private void updateBreadcrumbPath() {
        backFolderBtn.setEnabled(currentFolderId != null);
        if (currentFolderId == null) {
            breadcrumbLabel.setText("Location: Root");
            return;
        }
        List<String> pathParts = new ArrayList<>();
        String cursor = currentFolderId;
        while (cursor != null) {
            VaultItem folder = vaultManager.findItemById(cursor);
            if (folder == null) break;
            pathParts.add(0, folder.getName());
            cursor = folder.getParentFolderId();
        }
        breadcrumbLabel.setText("Location: Root / " + String.join(" / ", pathParts));
    }

    private void applyTableFilters() {
        String query = searchField.getText().trim();
        String category = (String) categoryFilterBox.getSelectedItem();

        List<RowFilter<Object, Object>> filters = new ArrayList<>();
        if (!query.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(query), 1, 2));
        }
        if (category != null && !"All Items".equals(category)) {
            filters.add(RowFilter.regexFilter(Pattern.quote("[" + category + "]"), 0));
        }

        tableSorter.setRowFilter(filters.isEmpty() ? null : RowFilter.andFilter(filters));
    }

    private void updateMetadataInspector() {
        VaultItem item = getSelectedVaultItem();
        if (item == null) {
            metaNameLabel.setText("Name: -");
            metaTypeLabel.setText("Type: -");
            metaSizeLabel.setText("Size: -");
            metaCreatedLabel.setText("Created: -");
            metaUuidLabel.setText("UUID: -");
            return;
        }
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        metaNameLabel.setText("Name: " + item.getName());
        metaTypeLabel.setText("Type: " + item.getType().name());
        metaSizeLabel.setText("Size: " + item.getSizeBytes() + " Bytes");
        metaCreatedLabel.setText("Created: " + df.format(new Date(item.getCreatedAtMillis())));
        metaUuidLabel.setText("UUID: " + item.getId().substring(0, 13) + "...");
    }

    private VaultItem getSelectedVaultItem() {
        int viewRow = vaultTable.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = vaultTable.convertRowIndexToModel(viewRow);
        String uuid = (String) vaultTableModel.getValueAt(modelRow, 1);
        return vaultManager.findItemById(uuid);
    }

    private void updateDriveSpaceIndicator() {
        File root = new File(".");
        long total = root.getTotalSpace();
        long free = root.getFreeSpace();
        if (total > 0) {
            double freeGb = free / (1024.0 * 1024.0 * 1024.0);
            double totalGb = total / (1024.0 * 1024.0 * 1024.0);
            int usedPct = (int) (((total - free) * 100L) / total);
            driveSpaceLabel.setText(String.format("Drive Storage: %.2f GB Free of %.2f GB", freeGb, totalGb));
            driveSpaceBar.setValue(usedPct);
        }
    }

    private char[] promptCryptoPassword(String promptText) {
        JPasswordField pf = new JPasswordField();
        int res = JOptionPane.showConfirmDialog(this, new Object[]{promptText, pf},
                "Zero-Knowledge Key Derivation", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res == JOptionPane.OK_OPTION) {
            return pf.getPassword();
        }
        return null;
    }

    private void styleInputField(JTextField field) {
        field.setMaximumSize(new Dimension(340, 34));
        field.setPreferredSize(new Dimension(340, 34));
        field.setBackground(BG_PRIMARY);
        field.setForeground(TEXT_LIGHT);
        field.setCaretColor(TEXT_LIGHT);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(71, 85, 105), 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));
    }

    private JButton createStyledButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFont(new Font("SansSerif", Font.BOLD, 12));
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private JLabel createMetaLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setForeground(TEXT_LIGHT);
        lbl.setFont(new Font("SansSerif", Font.PLAIN, 12));
        return lbl;
    }

    // ==================== Application Entry Point ====================

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            VaultMainUI app = new VaultMainUI();
            app.setVisible(true);
        });
    }
}
```