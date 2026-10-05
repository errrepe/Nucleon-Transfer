# TRANSFERS — Upload / Download / Fila

> MVP completo com fila persistente. Concorrência limitada 4–8 via TaskGroup.

## 1. Upload — drag-and-drop

### 1.1 Entrada

- SwiftUI `.onDrop(of: [.fileURL], ...)` → `[NSItemProvider]`.
- Cada provider com `hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)` → `loadItem(forTypeIdentifier:options:)` → `URL` (security-scoped, chamar `startAccessingSecurityScopedResource()`).
- Suporta arquivos + pastas. Preserva estrutura relativa ao ponto de drop.
- **Pasta de topo preservada (F8.2-R6):** soltar a pasta "Férias" cria
  `Férias/` na pasta de destino e sobe o conteúdo dentro dela
  (`LocalTreeScan.rooted` re-enraíza o scan sob o nome da pasta, NFC;
  `enqueueTree` cria a raiz como qualquer outra pasta). Várias pastas
  soltas juntas mantêm cada uma a sua raiz; arquivos soltos avulsos vão
  direto para a pasta atual. Pasta vazia também é criada. Conflito de nome
  na raiz segue `FolderConflictPolicy` (pasta existente com o mesmo nome →
  mescla dentro dela; arquivo com o mesmo nome → falha com mensagem).
- Acesso no sandbox (F8.2-R4): o grant da URL solta fica aberto só até os
  jobs daquele drop terminarem (done/failed/cancelled ou removidos); cada
  job lê o arquivo pelo próprio bookmark security-scoped, com
  `startAccessingSecurityScopedResource()` durante o job e `stop`
  balanceado, inclusive após relançar o app (entitlement
  `com.apple.security.files.bookmarks.app-scope`). Bookmark stale é
  recriado e persistido no job.
- Enfileiramento (F8.2-R2): bookmarks criados durante o scan (fora do
  MainActor) e um único `enqueueMany` por drop; snapshot com save
  coalescido (~500 ms), envelope versionado `{schemaVersion, jobs}`
  decodificado job a job, `.bak` do arquivo original se algo não
  decodificar, flush ao sair do app.

### 1.2 Enumeração recursiva

- `FileManager.enumerator(at:includingPropertiesForKeys:[.isDirectoryKey,.fileSizeKey,.isSymbolicLinkKey], options:[.skipsHiddenFiles])`.
- Resolve symlinks: segue se dentro da árvore, ignora / registra se apontar para fora (evita loop / leak).
- Coleta: `[(localURL, relativePath, isDirectory, size)]`.
- Ordenação topológica: diretórios por profundidade crescente (pais antes das filhas).

### 1.3 Criação de pastas remotas

- Para cada diretório em ordem topológica: `POST /drive/shares/{shareID}/folders`
  (`ParentLinkID`, `Name`, `Hash`, `NodeKey`, `NodeHashKey`, `NodePassphrase`,
  `NodePassphraseSignature`, `SignatureAddress` — exatamente 8 campos, SEM
  `XAttr`; verificado live 2026-09-30: pasta `NT-F42-*` criada, nome/HMAC
  lidos de volta com nosso código).
  Por pasta: gera keypair novo via `FolderCreate`/`NodeKeyGen` — chave
  TRANSFERÍVEL completa (primária tag 5 + UID `Drive key
  <noreply@protonmail.com>` tag 13 + auto-certificação tag 2 tipo 0x13 +
  subkey tag 7 + binding tag 2 tipo 0x18; blobs nus 5+7 são rejeitados com
  200501); nome cifrado com a Node key do pai + assinatura inline da address
  key (`MessageEncrypt.encryptSigned`); `Hash` = HMAC-SHA256 hex com a
  `NodeHashKey` do pai **decodificada de base64** (`NameHash`); `NodePassphrase`
  cifrada para o pai + assinatura detached da address key (`DetachedSign`).
- Convenções de assinatura live-verificadas (rclone-capturado): hash SHA-256
  (8, não SHA-512), salt `salt@notations.openpgpjs.org` de 16 bytes frescos
  por assinatura, creation-time crítica (0x82), issuer-fingerprint (0x21),
  OPS `nested=0x01` (quirk oficial), literais com data real. Sem o set de
  notation o servidor rejeita (200501).
- `SignatureAddress` = email do criador (validado; ID rejeita com 2501).
  Pastas NÃO carregam `XAttr` (ausente nas pastas oficiais).
  Share tipo Photo rejeita criação (2511) — criar só em shares Drive.
- Memoiza `relativePath → nodeID` em memória + persiste no `TransferJob` para retry idempotente.
- Conflito de nome (F7.1 R4): pasta existente com o mesmo nome → mescla
  (reusa o LinkID); arquivo com o mesmo nome → falha. Nunca sobrescreve
  nem renomeia silenciosamente (`FolderConflictPolicy`).

### 1.4 Chunking + encrypt + upload

- Tamanho de bloco versionado (`BlockFormatVersion`), default 4 MiB
  (`FileUpload.defaultBlockSize`, parâmetro em toda chamada).
- Por arquivo (F4.3, sem fila/UI — capturado do rclone, `FileUpload` +
  `DriveClient.uploadFile`):
  1. `POST .../links/{parent}/checkAvailableHashes {Hashes:[nameHashHex]}`
     (duplicate-name probe; rclone chama 2x idêntico — quirk, chamamos 1x).
  2. `POST .../shares/{id}/files` (draft, 10 campos: envelope pasta SEM
     `NodeHashKey` + `MIMEType` + `ContentKeyPacket`/`ContentKeyPacketSignature`
     no lugar; SEM `XAttr`) → `{File:{ID, RevisionID}}`.
  3. `POST /drive/blocks {AddressID, ShareID, LinkID, RevisionID, BlockList}`
     → `{UploadLinks:[{BareURL, Token, URL, Index}]}` (host de storage vem do
     `BareURL` em runtime, nunca hardcoded).
  4. `POST {BareURL}/storage/blocks` multipart (`Block`/`blob`,
     `application/octet-stream`, header `Pm-Storage-Token`) com os bytes do
     bloco cifrado.
  5. `PUT .../files/{linkID}/revisions/{revID} {ManifestSignature,
     SignatureAddress, XAttr}` → Code 1000.
- Semântica cripto verificada por decodificação dos blobs (detalhes em
  `Core/ProtonAPI/FileUpload.swift`): `ContentKeyPacket` = PKESK nu (96B,
  base64 sem armor) da chave de sessão de 32B para a subkey #18 do próprio
  node, auto-assinado pelo node; bloco = pacote SED tag-18 cru (chave de
  conteúdo, literal `""`), `Size` = tamanho cifrado (26B → 77B), `Hash` =
  base64(SHA-256 do bloco em claro, 44ch); `EncSignature` = literal sem
  assinatura da detached da hash do bloco (address key) cifrada para o node;
  `ManifestSignature` = address key sobre a concatenação das hashes cruas em
  ordem; `XAttr` = JSON `Common.{ModificationTime,Size,MIMEType,BlockSizes}`
  cifrado+assinado pelo node. VARIANT-UNCERTAIN (a confirmar live):
  entrada exata da manifest (raw vs base64-ascii), signatário do EncSignature
  (address vs node), schema exato do XAttr, `Hash` do bloco (claro vs cifrado).
- Arquivo 0 bytes: draft + commit direto (sem sessão de blocos, manifesto vazio).
- Falha de bloco: retry com backoff+jitter (ver §3), não reinicia arquivo inteiro se manifesto parcial existe.

### 1.5 Paralelismo

- `TaskGroup` global com `maxConcurrent = 4...8`.
- Cada arquivo ocupa 1 slot; blocos do mesmo arquivo podem usar sub-paralelismo sem exceder o teto global.
- Reduz para 2 em `429` / `5xx` consecutivos; restaura após janela limpa.

## 2. Download — pasta escolhida

### 2.1 Entrada

- `NSOpenPanel(directoryURL:canChooseFiles:false, canChooseDirectories:true, canCreateDirectories:true, prompt:"Choose destination")`.
- Destino `URL` com security-scoped bookmark persistido no job (para resume após relaunch).

### 2.2 Espelho da árvore

- Lista recursiva remota (`GET /drive/v4/nodes/{id}/children` + eventos) → constrói árvore.
- Cria diretórios locais primeiro (`FileManager.createDirectory(withIntermediateDirectories:true)`).
- Escreve via arquivo temporário `*.nucleon-part` → `rename` atômico ao verificar.
- Downloads em voo de antes do rename (RN1, 2026-10-03) podem ter deixado
  órfãos arquivos `*-part` com o prefixo antigo ao lado do destino: um retry
  no mesmo destino sobrescreve o órfão, e os demais são seguros de apagar.

### 2.3 Fetch + decrypt + verify

- Por arquivo: fetch session key → `GET` blocos em paralelo limitado → AES-CFB decrypt → SHA256 por bloco + MDC final.
- Mismatch: descarta bloco, retry; após N falhas marca job `failed` com `hashMismatch`.
- Preserva `mtime` se API fornecer.

## 3. Retry — backoff + jitter

```
delay = min(cap, base * 2^attempt) + random(0, jitter)
base = 1s, cap = 60s, jitter = 0..1s
retryable: timeout, 429, 500/502/503/504
non-retryable: 400, 401 (sem refresh), 403, 404, 422 (sem 2FA), HV 9001 (pausa)
maxAttempts por bloco = 5, por job = persistente com contador
```

- 429: respeita `Retry-After` se presente.
- HV 9001: pausa fila inteira, surface UI, resume manual.
- F8.2-R3 (implementado): `APIClient` preserva o status HTTP de 408/429/5xx
  mesmo com envelope Proton no corpo (`ProtonAPIError.http(status:code:message:retryAfter:)`;
  exceções: 9001 e 2028 em `/auth/`) e captura `Retry-After` (segundos ou
  HTTP-date). A fila classifica pelo status (408/429/5xx transitórios) e
  espera `max(backoff, Retry-After)` (Retry-After limitado a 5 min) + jitter.
  Cancelamento (`CancellationError`, `URLError.cancelled`, inclusive
  embrulhado em `.transport`) nunca é falha (F8.2-R1).
- Drafts (F8.2-R3): cada job tem um `ClientUID` persistido, enviado no
  draft (`ClientUID`, SDK C# `FileCreationRequest.cs`). Antes de criar o
  draft, e mais uma vez após um 2500, o probe `checkAvailableHashes` é
  comparado com o `ClientUID` (ou com o `draftLinkID` persistido por uma
  tentativa anterior); drafts nossos são apagados via `delete_multiple`
  no pai (Proton-API-Bridge `handleRevisionConflict`). Drafts de outros
  clientes nunca são tocados. Falha após o draft existir apaga o draft
  (best-effort, task não-cancelada).

## 4. Progresso / Pausa / Cancela / Retry

- `TransferJob`: `bytesTotal`, `bytesDone` atualizados por bloco (throttle UI 100ms).
- Pausa: flag persistida, Task atual termina bloco e suspende (não aborta bytes já enviados).
- Cancela: cancela Tasks, remove `.part`, marca `cancelled`, limpa draft remoto se API permitir.
- Retry manual: reseta `failed` → `queued`, mantém blocos completos (resume).
- Fila observável via SwiftData `@Query` + view-model `@Observable`.

## 5. Persistência

- SwiftData `TransferJob` + `TransferBlock` (ver `ARCHITECTURE.md` §8).
- Bookmark security-scoped do destino (download) e da origem (upload) para sobreviver a relaunch.
- Crash-safe: escreve estado após cada bloco commitado.

## 6. Edge cases

- Arquivo 0 bytes: cria node vazio, sem blocos.
- Nome com emoji / NFD vs NFC: normaliza NFC antes de comparar.
- Drop com 10k+ arquivos: paginação da coleta, sem bloquear main thread (`Task.detached` + progressivo).
- Disco cheio: pré-checa espaço (`URLResourceValues.volumeAvailableCapacity`), falha elegante antes de baixar.
- Rede cai: jobs `running` → `queued` no relaunch, resume de blocos.

## 7. F4.4 — fila de upload + UI drag-drop (implementado 2026-10-01, offline)

Arquivos: `Core/Transfers/TransferQueue.swift` (ator + `TransferFailure` +
`TransferRetryPolicy` + protocolos `TransferUploader`/`RemoteFolderCreator`),
`Core/Transfers/LocalTreeScan.swift` (coleta recursiva),
`Core/Transfers/DriveUploadAdapter.swift` (ponte live),
`Features/Transfers/TransferQueueView{,Model}.swift` (aba Uploads),
`NucleonTransferTests/TransferQueueTests.swift` (18 testes; suite 59/59 via
`swift test`; build Xcode verde, scheme `NucleonTransfer`,
DerivedData externo).

- Job: arquivo local → share/parent, estados
  queued/uploading/paused/done/failed/cancelled, `bytesTotal/Done`,
  `attempt` persistente, `maxAttempts` (default 5), `remoteLinkID` no sucesso.
- Persistência = snapshot JSON atômico em
  `Application Support/NucleonTransfer/transfer-queue.json` (NÃO SwiftData:
  um ator dono de um snapshot `Codable` tem menos modos de falha que um grafo
  `@Model` + `ModelContext`; só paths/IDs/progresso, NUNCA segredos —
  verificado por teste `snapshotHoldsNoSecrets`). `uploading` → `queued` no load.
- Concorrência: 3 uploads simultâneos, sequencial por job (caminho verificado
  `DriveClient.uploadFile`; blocos paralelos por job ficam diferidos, §1.5).
  Backoff em-slot: `min(60s, 1s·2^(n-1)) + jitter 0..1s`, `sleeper` injetável.
  Classificação: 429/5xx + `URLError` transitório → retry; resto permanente;
  desconhecido = permanente (retry é opt-in); HV 9001 → `pauseAll()`.
- Recursivo: `LocalTreeScan.collect` (relativos NFC estruturais — nunca strip
  de prefixo absoluto: FileManager canoniza `/tmp` → `/private/tmp`;
  symlinks seguidos só dentro da árvore, fora ignora+conta, loops por visited
  set, hidden skip) → `enqueueTree` cria pastas pai→filho via `ensureFolder`
  (memo por path relativo) e enfileira arquivos com `parentLinkID` resolvido.
- Adapter live: resolve keyrings por share raiz (`unlockShare`/`unlockNode` +
  `NodeHashKey` base64→32B, cache em memória), carrega bytes do disco,
  `uploadFile` + `progress(total)` no fim (granularidade por arquivo em F4.4;
  progresso por bloco é refactor futuro). `ensureFolder` tenta
  `nome`, `nome (1)`, `nome (2)` em erro `.api` (código exato de duplicata
  ainda VARIANT — confirma live em F4.5). Memo de pastas por sessão:
  jobs com parent de sessão anterior falham permanente com "re-add"
  (persistir `relativePath → nodeID` no job é F4.5, cf. §1.3).
- UI: aba Uploads (Browse | Uploads) com Picker de share destino (raiz do
  share), `NSOpenPanel` (arquivos+pastas, multi) + `.onDrop(of: [.fileURL])`,
  bookmarks security-scoped best-effort por arquivo, linhas com
  progresso/estado/pausar/retomar/cancelar/relaçar/remover + "Retry all failed".
- Retry F4.4 recomeça o ARQUIVO inteiro (sem resume de manifesto parcial —
  difere do aspirado em §1.4; resume de blocos é follow-up).

## 8. F5 — download de arquivos/pastas (implementado 2026-10-01, offline + rclone-capturado)

Arquivos: `Core/Transfers/FileDownload.swift` (núcleo puro: verify hash +
reassemble + destino + escrita atômica), `Core/Transfers/DriveDownloadAdapter.swift`
(ponte live: keyrings em memória, blocos paralelos, recursivo),
`Core/ProtonAPI/DriveClient.swift` (`listRevisions`/`getRevision`/`downloadBlockBytes`),
`Core/ProtonAPI/APIClient.swift` (`downloadRawBlock{,URL}` — octet-stream, sem envelope),
`Core/ProtonAPI/DriveModels.swift` (`RevisionBlock/Detail/Summary`),
`Core/ProtonAPI/AppVersion.swift` (`storageHeaderValue`),
`Features/Browser/DriveBrowserView{,Model}.swift` (botão Download por linha + progresso),
`NucleonTransferTests/FileDownloadTests.swift` (9 testes; suite 68/68 via
`swift test` — 59 anteriores intactos; build Xcode verde,
scheme `NucleonTransfer`, DerivedData externo).

- Descoberta (0 logins SRP frescos — token em cache de 23:55 reutilizado):
  `rclone --config /tmp/rclone-nt.conf cat "nt:NT-F43-FIXTURE.txt" --dump bodies`
  (`/tmp/f5ref/rclone-download.log` + redacted). Fluxo: `GET .../links/{fileID}`
  → `FileProperties.ContentKeyPacket` (b64 sem armor) + `ActiveRevision.ID` →
  `GET .../files/{id}/revisions` → `GET .../revisions/{revID}` →
  `Revision.Blocks[]={Index, Hash (b64 SHA-256 dos bytes CIFRADOS), Token (JWT
  curto), URL (token em-path), BareURL (host storage runtime), EncSignature}` →
  `GET {BareURL}` no host storage (`Pm-Storage-Token: Token`, Bearer + X-Pm-Uid,
  `x-pm-appversion: external-drive-rclone@1.75.1-stable`) → octet-stream do
  pacote SED tag-18 (77B p/ fixture 26B). Hash PROVADO = sha256(storage bytes),
  não plaintext (fixture Hash f854… ≠ sha256(plaintext) 0532…) — corrige o
  aspirado em §1.4/§2.3 que dizia "SHA-256 por bloco" ambíguo/claro.
- Download por arquivo: `unlockNode` (parent + address signers) →
  `FileUpload.openContentKey` (node candidates; cipher 7/8/9 aceito) →
  revision (activeRevision.ID, fallback última de `listRevisions`) → blocos em
  paralelo limitado (default 4, TaskGroup com janela deslizante) →
  `FileDownload.reassemble` (ordena por Index, checa contiguidade 1-based,
  verifica SHA-256 de CADA bloco antes de decriptar — fail-closed
  `hashMismatch`, `decryptBlock` SED/SEIPDv1 existente) → bytes idênticos.
  Arquivo 0 bytes: sem blocos, retorna `Data()` (paridade upload §1.4).
- Recursivo: `downloadTree` (arquivo → download direto; pasta →
  `listChildren` + `decryptName` com candidates da pasta, cria dirs locais
  primeiro, subpastas antes dos bytes, arquivos da pasta com paralelismo
  limitado default 4). Destino = pasta via `NSOpenPanel` (só diretórios,
  pode criar; `startAccessingSecurityScopedResource` best-effort na sessão,
  sem bookmark persistente — fila de downloads persistente é F6).
  Sobrescrita: `uniqueDestination` (`nome`, `nome (1).ext`, … — paridade
  upload) + escrita atômica `*.nucleon-part` → rename (§2.2).
- Decisão de escopo: downloader DEDICADO com progresso próprio (não extensão
  do `TransferQueue` — `TransferJob` é upload-específico: localPath/parentLinkID/
  uploader; adaptar para download balloonaria o ator + persistência; F6 unifica).
- UI (browser): botão "Download" por linha (arquivo e pasta) + `NSOpenPanel`
  destino; progresso por blocos no arquivo (`0/total` + barra) e status por
  arquivo na pasta; estado `downloading`/`downloadProgress`/`downloadStatus`
  no view-model (sem fila persistente em F5).
- Testes offline (9, sem rede): roundtrip single/multi-bloco (incl. ordem
  reversa), vazio, `hashMismatch` fail-closed + base64 ruim, gap de índice,
  chave errada rejeitada, sufixo ` (1)` ext-aware, escrita atômica, regra
  26B→77B + `Hash == sha256(ciphertext)` (paridade fixture live).

## 9. F6 — hardening alpha (implementado 2026-10-01, offline + probe live pronta)

Arquivos novos: `Core/Transfers/UserFacingError.swift` (mensagens acionáveis),
`Core/Transfers/DownloadRecord.swift` (modelo puro),
`Features/Transfers/TransferActivityStore.swift` (histórico + refresh),
`NucleonTransferTests/F6HardeningTests.swift` (25 testes; suite 93/93 via
`swift test` — sem regressão; build Xcode verde,
scheme `NucleonTransfer`, DerivedData externo).
Alterados: `DriveModels.ShareMetadata` (Bool tolerante),
`TransferQueueView{,Model}` (aba Transfers unificada),
`DriveBrowserView{,Model}` (spinners/vazios/refresh),
`ContentView` (Browse | Transfers), `LoginViewModel` + `ProtonAPIError`
(2028 com espera ~10min).

- Unificação mínima (F5 deixou downloader dedicado; SEM reescrever
  `TransferQueue`): `TransferQueue` continua upload-only
  (localPath/parentLinkID/uploader). Downloads ganham registro leve
  (`DownloadRecord`: nome/kind/state/fileCount/destino — sem segredos) num
  `TransferActivityStore` `@Observable` compartilhado: o browser reporta
  início/fim/falha, a aba Transfers (ex-Uploads) mostra uploads + downloads
  juntos, com "Clear finished". Nenhum ator reescrito, nenhuma persistência nova.
- Erros acionáveis: zero `print` em paths de usuário (auditoria: nenhum
  `print`/`NSLog` no app); todo erro de rede/crypto/API passa por
  `UserFacingError.message(for:)` antes de chegar à UI (status, downloadStatus,
  jobRow, login). 2028 → "espere ~10 minutos, não logue repetidamente, reuse
  a sessão"; 9001 → "abra drive.proton.me, complete o check, fila pausada";
  429 → "backing off, deixe a fila rodando"; 5xx → "retry automático";
  401 → "sign in novamente"; 2511 → "use share Drive"; hashMismatch →
  "retry, se persistir re-upload". Strings persistidas (`errorMessage`) são
  re-mapeadas por heurística (`message(forMessage:)`) na exibição.
- Consistência pós-operação: `TransferActivityStore.browserRefreshCounter`
  é bumpado ao enfileirar árvore (pastas criadas), ao completar upload (job
  → done via listener) e ao concluir download; `DriveBrowserView` observa
  (`onChange`) e recarrega. Spinners: shares/loading no Transfers e vault no
  browser (`isLoading`/`isLoadingShares`/`isAdding`); vazios: "No uploads
  yet…", "No downloads yet…", "No shares…", "Empty folder…".
- `ShareMetadata.locked`/`volumeSoftDeleted` (`Bool?`): mesmo risco do
  Thumbnail (Go pode enviar 0/1). Tornados tolerantes com `init(from:)`
  custom: aceita Bool, Int/Int64 (0/1), `"true"/"false"/"0"/"1"`,
  null/ausente → nil; encode como Bool (paridade Thumbnail). Cobertura
  offline em `ShareMetadataBoolTests`; auditoria live via JSON bruto em
  `/drive/shares?ShowAll=1` (tipos impressos por campo, sem segredos) na
  bateria F6 — resultado a anexar após o run.
- Limpeza conta de teste: listar antes de tocar (nomes decriptados), NUNCA
  tocar no fixture `NT-F43-FIXTURE.txt` (link `9emt5ME9I1iaIHp4IA_I5g`).
  Alvos: resíduos `NT-F4*`/`NT-OK`/`NT-DRAFT` ativos → `trash_multiple`;
  2 arquivos em trash → `delete_multiple` NÃO se aplica a trashed (2501
  "Draft file not found", provado probe8) — documentado e deixado;
  pastas `f4ZGLjN_5Fup42szCV1Fgw`, `45lNNiysRU2I4jYC09HS-w` ativas → trash.
  Se algum delete exigir endpoint desconhecido, documentar e deixar.
- Verificação live (código do PRODUTO, 1 login SRP, resto reusa sessão;
  espaçamento ~11min entre SRPs frescos; credenciais SÓ via env
  `NT_USER`/`NT_PASS`, nunca em disco; probes em `/tmp`, rclone temp apagada
  após uso): bateria `/private/tmp/nt-f6live` (SPM executável, módulo único,
  `swift build -c release`, sem segredos no output):
  `NT_USER=… NT_PASS=… /private/tmp/nt-f6live/.build/release/nt-f6live`
  faz unlock → shares bruto → lista decriptada → trash resíduos ativos →
  sobe `NT-F6-a.txt` + `NT-F6-sub/NT-F6-b.txt` via `TransferQueue` +
  `DriveUploadAdapter` → baixa via `DriveDownloadAdapter` → `cmp`
  byte-idêntico + SHAs impressas → trash dos `NT-F6-*` (conta limpa).
   Último SRP fresco conhecido ~02:05 (−03); probe falha rápido (exit 3) sem
   env e (exit 4) em 2028 sem retry.
- Auditoria shares-raw (mesma bateria, linhas 4-6): `Locked=Bool`,
  `VolumeSoftDeleted=Bool` nos 2 shares — o modelo tolerante (`Bool` /
  Int 0-1 / string / null) era defensivo (paridade Thumbnail); o fio manda
  Bool hoje, o decode tipado passa (`shares-typed-ok count=2`).
- Gate allowlist `/drive/blocks` como LIMITADOR do alpha (mesma bateria,
  linhas 28-32; 1 draft real + 1 bloco, mesma sessão, sem login extra):
  produto (`external-drive-nucleon_transfer@0.1.0-alpha`; a sonda rodou
  antes do rename, com o header do nome antigo) → 2000
  "You are using an outdated version of the app. Please update to upload
  this file."; versão honesta alta
  (`external-drive-nucleon_transfer@1.75.1-stable`, idem) → 2000 idêntico;
  string rclone exata (`external-drive-rclone@1.75.1-stable`) → 1000.
  Allowlist ESTRITO pela string completa (bump honesto NÃO passa) →
  decisão SEM spoofing (ramo 3): uploads diretos SEGUEM DESABILITADOS no
  alpha (`UserFacingError.uploadAllowlisted`, ramo `api code == 2000` + heurística
  `"2000"+"outdated"`, cobertura `api2000UploadAllowlistHonest` /
  `api2000StringHeuristic`). Download FUNCIONA com produto: `GET` no storage
  host com header produto → HTTP 200, 77B (fixture, read-only, linha 32).
- Bug live da mesma bateria (linhas 35-36): `NT-F6-a.txt` falhou com decode
  (`api 1000: … body={"AvailableHashes":[],"PendingHashes":[{Hash,
  RevisionID, LinkID, ClientUID:null}],"Code":1000}`) — um draft residual
  state=0 deixou o hash pending e o servidor retornou OBJETOS em
  `PendingHashes`, mas o modelo era `[String]` (única forma na referência
  rclone `/tmp/f43ref/resp-2/3.json`, sempre `[]`). Corrigido offline:
  `PendingHash {Hash?, RevisionID?, LinkID?, ClientUID?}` (tudo opcional, a
  lista é só informative — o upload a ignora), cobertura
  `CheckAvailableHashesTests` (vazio rclone + objeto live corpo integral).
  Corpo integral já estava no erro (dentro do prefixo 600B do `APIClient`,
  ~230B — sem truncamento, sem probe extra). `NT-F6-b.txt` falhou com o
  `api 2000` esperado (gate). Roundtrip `0/2` (linha 37); draft state=0
  `3UaNbhkZFWhbrHmkKDQgIQ` + trash do draft do gate pendentes (trash do gate
  falhou com 2501 signature-address, linha 33 — retry após relogin).
- Como testar (offline): `swift test` na raiz do repo (o `Package.swift`
  compila `Core/` direto; 93/93 esperado) + build Xcode MCP scheme
  `NucleonTransfer`
  (DerivedData `/Volumes/SSD 4TB/DEV/DerivedData`, sem builds concorrentes).

## 10. F6-fix — `runModal` travava a main thread (corrigido 2026-10-01, offline)

Bug real confirmado via `sample` (`/tmp/nt-sample.txt`): main thread presa em
`DriveBrowserViewModel.pickAndDownload` (`DriveBrowserViewModel.swift:120`) →
`[NSSavePanel runModal]` → modal loop eterno. Quando o app não está ativo/key
(ou o painel não pode apresentar), `runModal()` nunca retorna: UI inteira
morre (abas, Reload, botões), só AX/screenshots respondem.

- Fix: `pickAndDownload` (`Features/Browser/DriveBrowserViewModel.swift`) e
  `addPanel` (`Features/Transfers/TransferQueueViewModel.swift`) agora
  apresentam o `NSOpenPanel` de forma assíncrona — sheet via
  `beginSheetModal(for:)` na janela key, fallback `begin` app-modal quando não
  há janela key — e continuam no completion via `withCheckedContinuation`
  (suspensão, nunca bloqueio do MainActor). Cancel/dismiss apenas resolve nil:
  download seta `downloadStatus = "Download cancelled (<nome>)"`; upload é
  no-op (status intocado). Nenhum `runModal` restante no produto (grep prova).
- Decisão extraída para núcleo puro AppKit-free
  (`Core/Transfers/PanelIntake.swift`: `downloadDestination(responseOK:url:)`,
  `uploadURLs(responseOK:urls:)`, `downloadCancelledStatus(rowName:)`), coberta
  por `NucleonTransferTests/PanelIntakeTests.swift` (7 testes Swift Testing;
  suite 100/100 via `swift test` — 93 anteriores intactos; build Xcode
  verde, scheme `NucleonTransfer`, DerivedData externo).
- Auditoria MainActor nos paths de UI: `panel.url` após cancel agora guarda
  `response == .OK` primeiro (valor stale ignorado); download segura
  `startAccessingSecurityScopedResource` só durante o `download` e dá `stop`
  ao fim; intake de upload mantém o grant da sessão de propósito (a fila lê os
  arquivos depois via bookmarks — parar cedo revogaria o acesso); scan de
  diretórios em `add(urls:)` saiu do MainActor (`Task.detached`, spinner via
  `isAdding`); login segue sem deadline global (cada request tem o timeout
  padrão da URLSession; UI continua responsiva em `signingIn` com botão
  desabilitado — deadline global é follow-up, não hang).
- Wart visual menor (screenshots 559×450): pills Browse/Transfers sobrepunham
  o "Signed in" — `ContentView` ganhou `padding(.top, 28)` + `minHeight: 30`
  no header para dar clearance em janelas compactas.
