# AUTH — SRP, 2FA, Session (memória, sem Keychain)

> Endpoints oficiais apenas. Header obrigatório: `x-pm-appversion: external-drive-nucleon_transfer@0.1.0-alpha`.

## 1. Fluxo completo

```
1. POST /auth/v4/info { Username }
   → { Version, Modulus (hex), ServerEphemeral (hex), Salt, SRPSession }

2. SRP-6a local:
   clientEphemeral (A), clientProof (M1) = H(A, B, S)
   usando password + salt + modulus

3. POST /auth { Username, ClientEphemeral, ClientProof, SRPSession }
   → 200 { AccessToken, RefreshToken, UID, ExpiresIn, Scope }
   → 422 com 2FA required → passo 4
   → 400/401 → erro auth (ver §5)
   → 9001 → Human Verification exigida

4. (se 2FA) POST /auth/v4/2fa { TwoFactorCode, SRPSession }
   → 200 tokens como acima
   Suporta TOTP (6 dígitos). `otp_secret` para setup não é usado no MVP
   além de exibir instrução se conta exigir enrollment (fora de escopo).

5. Unlock hierarchy (F3b-1 implementado para user keys):
   a. `GET /core/v4/keys/salts` (só com escopo de password, logo após login)
      → salt da primary user key.
   b. `saltedKeyPass = bcrypt(keyPass, dotSlash(keySalt))[-31:]`
      (semântica rclone `SaltForKey`; NUNCA a senha crua — validado: pgpy
      independente também rejeita a senha crua). Só em memória (nunca disco);
      seeds destravadas idem (`KeyringCache` actor, `lock()` limpa).
   c. `GET /core/v4/users` → user keys armored → parse pacotes → S2K iterado
      + AES-CFB puro a partir do IV (SEM prefixo random nessas chaves Proton:
      secretData é exatamente MPI + SHA-1 — verificado por hexdump) →
      seed verificada contra a pública (Ed25519 direto; X25519 com bytes
      reversos BE→LE). `GET /core/v4/addresses` → address keys (Token, F3b-2).
   d. F3b-2/3 implementado e verificado OFFLINE (aguardando cooldown do
      rate-limit 2028 para validação live): PKESK-ECDH decrypt (KDF RFC 6637 §8
      + AES-KW RFC 3394 + checksum/padding — interop total contra PKESK
      sintético gerado em Python), SED/SEIPDv1 decrypt + literal parse,
      Ed25519 detached v4 verify (roundtrip), fingerprints v4 (iguais ao pgpy),
      `MessageDecrypt` (tenta cada seed candidata) e `unlockAddressKeys`
      (Token→passphrase→address key). Tudo em `Core/Crypto/PGP/`.
   e. Rate limit: logins repetidos retornam `2028 Too many recent logins`.
      Nunca retry em loop no `/auth/v4`; backoff + espaçar logins (cada
      bateria de teste usa UM login).

6. Sessão em memória:
   `ProtonSession{uid,accessToken,refreshToken}` só no `SessionManager` actor.
   Sem Keychain, sem disco — re-login a cada launch (como o app oficial).

7. Refresh (reativo, sem timer):
   POST /auth/v4/refresh { RefreshToken, UID }
   → novos Access+Refresh (rotativo). Disparado só quando uma chamada
   autenticada volta 401 (`SessionManager.withAuth`); não há refresh
   agendado por `expiresIn`.
   - Single-flight: um único `refreshTask` por vez. 401s concorrentes
     aguardam o mesmo refresh em vez de reenviar o refresh token (que a
     Proton rotaciona — reuso falha e pode revogar a sessão).
   - Se o token que falhou já foi trocado por outro chamador, o retry usa o
     token atual sem novo refresh.
   - Epoch de sessão: login/signOut incrementam o `epoch` e cancelam o
     refresh em voo; um refresh que termina sob outro epoch descarta o
     resultado (`.unauthorized`), então nunca ressuscita sessão deslogada.
   - Redirects: a `URLSession` só segue 3xx para o mesmo host https
     (`RedirectGuard`); redirect para outro host é recusado e vira `.http(status: 3xx)`.

8. Logout / revoke:
   DELETE /auth/v4 (best-effort, depois de limpar a sessão local). Limpa sessão + seeds da memória (zeragem best-effort, ver §4).
```

## 2. SRP-6a detalhe

- Implementação nativa Swift, sem binding incubating.
- BigInt: `Core/Crypto/BigUInt.swift` próprio, limbs de 32-bit (toda intermediação
  cabe em `UInt64`, sem carry/borrow wrap). Wire little-endian igual a go-srp.
  Verificado contra Python: mul exato, `pow(a,3,2^256-1)` exato, consistência `q·m+r==d`.
- Hash: `expandHash = SHA512(d||0)||SHA512(d||1)||SHA512(d||2)||SHA512(d||3)` (256 bytes),
  `M1 = expand(A||B||S)`, `M2 = expand(A||M1||S)` verificado do servidor, gerador sempre 2, 2048-bit.
- Password v3/v4: `bcrypt($2y$10$, dotSlashBase64(salt+"proton"))` + expand. Bcrypt vendored
  (`Core/Crypto/BCrypt/`, motor EksBlowfish próprio + tabelas Blowfish MIT de
  vapor-community/bcrypt, ver `docs/VENDORED.md`). Semântica idêntica ao fork
  ProtonMail/bcrypt (primeiros 22 chars do salt, eco no output). Validado contra
  bcrypt de referência (Python): 3 vetores incluindo senha UTF-8.
- Modulus PGP-clearsign: assinatura verificada (`ModulusDecoder`, F8.1-S1) contra a pubkey
  SRP da Proton fixada (copiada do go-srp `modulusPubkey`); módulo sem assinatura é rejeitado.
- **Login real verificado em 2026-09-29** contra a conta de teste dedicada
  (registrada sob o nome antigo do app, `@proton.me`; endereço completo nos
  relatórios de QA no Desktop):
  info → hash → proofs → `/auth/v4` → serverProof OK → UID recebido. Credenciais
  usadas só em memória, nunca commitadas.
- Perf conhecido: ~6s por modPow 2048-bit em debug (≈20s por login). Release é
  ~5-10x mais rápido. Otimizar (Montgomery/janela deslizante) só se virar gargalo real.
- Nunca logar `password`, `S`, `K`, `M1`, salt raw. Logs só com prefixos truncados para debug local opt-in.
- Vetores de referência: `go-proton-api` (SRP), `rclone` backend protondrive.

## 3. 2FA

- `POST /auth/v4/2fa` com `{ TwoFactorCode: "123456" }`.
- TOTP de 30s — validar skew de relógio via NTP antes de acusar código inválido.
- Erros comuns: `8002` (código inválido/expirado), `8101` (muitas tentativas → backoff).
- Fora de escopo MVP: FIDO2 / hardware key enrollment. Mensagem clara se conta exigir.

## 4. Sessão em memória (sem Keychain)

- Como o app oficial: sessão (`ProtonSession{uid,accessToken,refreshToken}`,
  `SessionManager` actor) vive SÓ em memória e morre no logout/quit.
  Re-login a cada launch; refresh single-flight (sob demanda, no 401)
  mantém a sessão viva.
- Nunca em Keychain, UserDefaults, SwiftData, plist, logs, crash reports.
- Seeds destravadas idem: só em `KeyringCache` (memória), `lock()` zera e limpa.
- Zeragem é best-effort (`SecureBytes`, `memset_s`): o app zera os buffers
  que possui (estado do bcrypt, hash da senha, senha salgada, passphrases
  decifradas, seeds no `lock()`/`reset()`). A `String` do campo de senha,
  cópias feitas pelo runtime, objetos de chave do CryptoKit e `Data` ainda
  compartilhada (copy-on-write) não têm garantia de zeragem — só são
  liberadas.

## 5. Erros comuns

| Código / HTTP | Significado | Ação |
|---|---|---|
| 400 Bad Request | payload SRP inválido | re-gerar A/M1, checar hex padding |
| 401 Unauthorized | proof errado / senha errada | não retry cego, pedir senha |
| 422 2FA required | falta TOTP | pedir código, POST /auth/v4/2fa |
| 8002 | TOTP inválido | checar NTP skew, pedir novo código |
| 9001 HV required | Human Verification | pausar fila, abrir fluxo HV, retry após |
| 429 | rate limit | backoff exponencial + jitter, reduzir paralelismo |
| 500/502/503 | transitório servidor | retry limitado, surface após N tentativas |

## 6. NTP / Clock skew

- Antes de SRP e TOTP, faz `HEAD` ou lê `Date` header da resposta `/auth/v4/info`.
- Se `abs(serverDate - localDate) > 60s`, avisa usuário e ajusta cálculo TOTP / expiração.
- Não altera relógio do sistema, só corrige lógica de expiração local.

## 7. Referências de implementação

- `go-proton-api` — fluxo SRP + unlock hierarchy (Go, leitura obrigatória).
- `rclone` backend `protondrive` — chunking + retry + mapeamento de erros.
- SDK oficial `ProtonDriveApps/sdk` — apenas `Client` como referência de endpoints; auth/session/address provider NÃO vêm do SDK e devem ser implementados aqui.
- `sdk-swift` (binding C# → Swift, 2 commits, instável) — explicitamente NÃO usado (ver `SDK-STRATEGY.md`).

## 8. Segurança

- Zero telemetria de credenciais. Nenhum log com tokens/keys.
- `AccessToken` e `RefreshToken` só em memória (`SessionManager` actor).
- Veja `SECURITY.md`.
