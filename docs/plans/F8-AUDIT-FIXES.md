# F8 — Resolver todos os achados da auditoria (2026-10-04)

## Contexto

A auditoria de 5 agentes ([docs/AUDIT-2026-10-04.md](docs/AUDIT-2026-10-04.md)) encontrou:
- falhas de segurança: módulo SRP sem verificação; assinaturas opcionais na cadeia de decrypt; path traversal;
- bugs de concorrência e robustez: refresh de token, fila de uploads, cancelamento;
- gargalos medidos: AES-CFB 40× lento, enqueue O(n²), arquivos inteiros em RAM;
- problemas de UI/UX: trash pelo menu de contexto apaga os itens errados, fluxo de 2FA, erro 2000;
- funções esperadas que faltam: tamanhos reais, renomear, mover, lixeira, Quick Look etc.

Objetivo: corrigir tudo em fases, cada uma num branch com PR próprio. A implementação é feita por subagentes Opus 5.5 e eu atuo como orquestrador.

Decisões do mantenedor (2026-10-04):
- **Escopo:** tudo, em fases.
- **Pasta de topo:** preservar. Soltar "Férias" cria `Férias/` no destino, tanto no upload quanto no download.
- **Login salvo:** opt-in "Manter conectado", com "Exigir Touch ID" opcional. Atualizar README, SECURITY.md e AUTH.md e criar a ADR-004.
- **Entrega:** um branch e um PR por fase. O commit nos branches está autorizado.

Fora do escopo, conforme a própria auditoria recomendou: links de compartilhamento e "Compartilhados comigo", cópia (exige re-upload, que está bloqueado), múltiplas contas e janelas, Share extension, App Intents e esquema de URL, Sparkle, limite de banda, busca global e UI de HV 9001. Cada um vira uma issue no backlog.

## Orquestração

- **Primeiro passo:** copiar este plano para `docs/plans/F8-AUDIT-FIXES.md`. Ele herda as regras da F7 (`docs/plans/F7-NATIVE-UI.md` §0.2, §3, §4, §10), com os caminhos atualizados para `Nucleon Transfer`.
- **Exceção explícita à F7 §3.2:** as fatias da Fase 1 e da Fase 3 podem alterar `Core/Crypto/**`, `DecryptChain`, `FileUpload`, `FileDownload` e `SessionManager`, desde que mantenham os testes de vetores verdes e adicionem novos.
- **Uma fatia por subagente:** `Agent(subagent_type: general-purpose, model: opus)`.
  - O prompt inclui as regras globais da F7 §3, a fatia inteira e os achados citados, com `file:line` do relatório de auditoria.
  - O subagente devolve o relatório no template da F7 §10.
- **Paralelismo:**
  - Só para fatias marcadas ⟂ que não compartilham arquivos, e cada uma com `isolation: "worktree"`.
  - Nunca dois builds ao mesmo tempo.
  - `swift test` pode rodar em paralelo em worktrees distintos.
- **Depois de cada fatia, eu:**
  1. leio o `git diff`;
  2. rodo `swift test` e `BuildProject`;
  3. rodo `code-review` em nível medium;
  4. faço o commit (`fix(security): F8.1-S2 …`, com a linha Co-Authored-By).
- **Fim de fase:**
  - Faço push do branch, abro o PR com `gh pr create` e vinculo com `ccd_pr`.
  - Listo os "Live checks for human" no corpo do PR.
  - A fase seguinte parte da `main`, se o PR já foi mergeado; senão é empilhada sobre o branch anterior.
- **Agentes nunca fazem login real.** Tudo o que depende de conta vai para os "Live checks for human" do PR.
- **Endpoints novos:** cada um é conferido no SDK C# (`ProtonDriveApps/sdk`) ou no `go-proton-api`, com a fonte citada num comentário `///`.

## Fase 1 — Segurança · branch `fix/f8-1-security`

| Fatia | O que fazer | Arquivos principais |
|---|---|---|
| S1 ⟂ | Verificar a assinatura do módulo SRP. Embutir a pubkey SRP da Proton (copiada do `go-srp`, citando a fonte), verificar o clearsign com `DetachedSig.verify` e rejeitar módulo sem assinatura. Também: checar o retorno de `SecRandomCopyBytes` e lançar erro em vez de usar segredo fora do intervalo; rejeitar auth version < 3. | `Core/Crypto/ModulusDecoder.swift`, `SRPClient.swift`, `PasswordHash.swift`, `SessionManager.swift:71,120` |
| S2 | Assinaturas obrigatórias (fail-closed) nas passphrases de share e node (`DecryptChain.swift:28,48`), no Token da address key (`KeyringCache.swift:70`) e no NodeHashKey (`NodeKeyResolver.swift:36`). Nomes, manifesto, ContentKeyPacket e blocos: verificar, e em caso de falha marcar `DriveItem.signatureIssue` e mostrar um badge de aviso, como fazem os clientes oficiais, em vez de bloquear. Download com manifesto inválido falha com erro claro. | `Core/Security/*`, `DriveDownloadAdapter.swift`, `FileDownload.swift`, `DriveItem.swift` |
| S3 ⟂ | Endurecer o PGP: rejeitar SED tag 9 sem MDC; comparar o MDC em tempo constante; recusar MD5 e SHA-1 em `DetachedSig`. | `MessageDecrypt.swift`, `SEDDecrypt.swift`, `DetachedVerify.swift`, `PGPHash.swift` |
| S4 ⟂ | Endurecer a rede: `URLSession` dedicada com `.ephemeral`, `urlCache = nil`, sem cookies e com timeouts. Validar a URL de storage (https e sufixo `.proton.me` / `.protonmail.ch`) antes de enviar Bearer ou UID. Carregar o status HTTP no erro. | `Core/ProtonAPI/APIClient.swift` |
| S5 ⟂ | Sanitizar nomes remotos ao gravar no disco: rejeitar `.`, `..`, nome vazio e NUL; trocar `/` e `:`; checar que o caminho padronizado continua sob o destino. Usar o helper em todo `appendingPathComponent` com nome remoto. | novo `Core/Transfers/SafeFilename.swift`, `DriveDownloadAdapter.swift`, `FileDownload.swift` |
| S6 | Refresh single-flight: um `refreshTask` compartilhado; `withAuth` reutiliza o token novo se ele já rodou; epoch de sessão para impedir que um refresh termine depois do signOut e escreva a sessão de volta. | `Core/ProtonAPI/SessionManager.swift:35-44,109-126` |
| S7 | Higiene: zerar os buffers `[UInt8]` de `salted`, `hashed`, bcrypt e passphrases com `memset_s`. Reescrever as promessas de zeragem no README, SECURITY.md e AUTH.md como "best-effort". Alinhar o entitlement `read-write` com `ENABLE_USER_SELECTED_FILES`. | `AppSession.swift`, `ProtonBcrypt.swift`, `KeyringCache.swift`, docs, `project.pbxproj` |

Testes novos:
- módulo: assinatura válida, adulterada e ausente;
- passphrase sem assinatura → erro;
- SED tag 9 → erro;
- `SafeFilename`: `..`, `a/b`, NUL, unicode;
- refresh: 10 chamadas concorrentes geram 1 request (com um `APIClient` mock via protocolo);
- host de storage inválido → erro.

Live checks: um login real verifica o módulo assinado e as assinaturas presentes em dados reais, incluindo pastas e arquivos antigos.

## Fase 2 — Robustez · branch `fix/f8-2-robustness`

| Fatia | O que fazer | Arquivos |
|---|---|---|
| R1 | Fila de uploads, correções de estado: token de geração por run (pause/resume não roda o job 2×); erros de jobs que não estão mais `.uploading` são ignorados; `URLError.cancelled` vira cancelamento, não falha; `remove` não libera `inFlight` enquanto o job ainda roda. | `Core/Transfers/TransferQueue.swift` |
| R2 | Fila de uploads, persistência e escala: `enqueueTree` → `enqueueMany` único, com bookmarks criados no scan; save com debounce de ~500 ms e flush em estados terminais e ao sair; decode job a job com `schemaVersion` e backup em `.bak` se falhar; FIFO de ids na fila. | `TransferQueue.swift`, `UploadCoordinator.swift` |
| R3 | Retry e drafts: classificar pelo status HTTP (429/5xx transitórios, honrando `Retry-After`; 401 do storage → refresh); persistir os ids do draft (link/revision) no job para retomar ou apagar; usar o resultado de `checkAvailableHashes` / ClientUID. | `APIClient.swift`, `DriveClient.swift:209-265`, `TransferQueue.swift` |
| R4 ⟂ | Sandbox e retomada: `startAccessingSecurityScopedResource()` no bookmark resolvido, com stop balanceado; regravar bookmark stale; entitlement `files.bookmarks.app-scope`; liberar os escopos que a `UploadCoordinator.swift:107` mantém abertos. | `DriveUploadAdapter.swift:110-126`, `UploadCoordinator.swift`, entitlements |
| R5 | Downloads: reservar nomes no actor (set case-folded por diretório); mover sem `removeItem` e, se o destino existir, tentar novo sufixo; Task handle para cada download, com cancelamento e cancelamento de todos no signOut via epoch; progresso que chega depois do fim é descartado. | `DriveDownloadAdapter.swift`, `FileDownload.swift`, `DownloadCoordinator.swift`, `BrowserModel.swift:210`, `AppSession.swift:146` |
| R6 | Preservar a pasta de topo: o upload cria a raiz do scan e o download cria a subpasta da pasta baixada. Atualizar TRANSFERS.md. | `UploadCoordinator.swift:114-131`, `TransferQueue.swift:287`, `DriveDownloadAdapter.swift:156` |
| R7 ⟂ | Sessão e browser: token de request por pasta em `BrowserModel.load`; 401 só faz signOut se a listing for a atual; 2FA errado mantém `.needsTwoFactor` com erro inline e sub-estado `.verifyingTwoFactor`; falha de unlock roda a limpeza completa. Também a fila vinculada à conta (B12): jobs carregam o `userID` e os de outra conta ficam ocultos e pausados. | `BrowserModel.swift:105-131`, `AppSession.swift:111-135`, `TwoFactorView.swift`, `TransferQueue.swift` |
| R8 ⟂ | Trash pelo menu de contexto: `pendingTrash` recebe os ids clicados; toolbar e ⌘⌫ passam a seleção. | `FolderTable.swift:107`, `FolderView.swift:119-124`, `BrowserModel.swift` |

Testes:
- pause → resume com uploader lento gera um único commit;
- cancelamento não vira falha;
- JSON com um job inválido não perde os demais;
- 3k arquivos enfileirados em menos de 1 s;
- colisão `A.txt` / `a.txt`;
- pasta de topo preservada (`LocalTreeScan` / `PanelIntake`);
- policy do 429 com `Retry-After`.

## Fase 3 — Performance · branch `perf/f8-3`

| Fatia | O que fazer | Arquivos |
|---|---|---|
| P1 ⟂ | AES-CFB com um único `CCCryptorCreateWithMode(kCCModeCFB)`: sem resync (tag 18) usa IV zero sobre prefixo + dados; com resync usa IV `c[2..<18]`; saída em buffer pré-alocado. Também: cortar as ~7 cópias por bloco no decrypt e calcular o MDC com SHA-1 incremental. Meta: 4 MiB em menos de 5 ms. | `AESBlock.swift`, `SEDEncrypt.swift`, `SEDDecrypt.swift`, `Packets.swift` |
| P2 | Pipeline em streaming (B1): `prepareUpload` vira "material do draft" mais encrypt por bloco, `nonisolated` ou `@concurrent`, fora do actor `DriveClient`; leitura com `FileHandle` em chunks de 4 MiB; TaskGroup de 3–4 blocos por upload com progresso por bloco. Download: verificar, decifrar e gravar em `.nucleon-part` por `FileHandle`, com janela de reordenação; decrypt fora do actor. | `FileUpload.swift`, `DriveClient.swift`, `DriveUploadAdapter.swift`, `DriveDownloadAdapter.swift`, `FileDownload.swift` |
| P3 ⟂ | Browser: cache de `visibleItems` por pasta, recalculado só quando mudam os itens, o sort ou o filtro; hover só durante drag, ou isolado numa subview; estado `@Observable` por pasta; paginação para quando `count < pageSize` (fica como live check); decrypt de nomes em paralelo num helper nonisolated. | `BrowserModel.swift`, `FolderView.swift`, `FolderTable.swift`, `DriveClient.swift:48-71`, `DriveListing.swift:49-70` |
| P4 ⟂ | Criação de pastas em paralelo por nível de profundidade (limite de 4). | `TransferQueue.swift:305-313` |
| P5 ⟂ | `BigUInt.modPow` com Montgomery CIOS e janela fixa de 4–5 bits; `EksBlowfish` com unsafe buffers. | `BigUInt.swift`, `BCrypt/EksBlowfish.swift` |

Antes de começar, promover o benchmark do scratchpad para `Benchmarks/`: um target executável fora do test target. Cada fatia mede antes e depois e cola os números no PR.

## Fase 4 — UI/UX e acessibilidade · branch `feat/f8-4-ux`

- **U1, upload bloqueado:**
  - flag `uploadsBlocked` depois do primeiro erro 2000;
  - banner único via `safeAreaInset(.top)` com "Learn More";
  - Upload desabilitado, com `.help`;
  - texto curto por linha.
- **U2, erros** (`UserFacingError.swift`):
  - reescrever no formato "o que aconteceu + o que fazer", com o código entre parênteses;
  - regex com word boundary para 5xx e remover o match de `"photo"`.
- **U3, browser:**
  - banner "Couldn't refresh" quando há cache;
  - ⌘⌫ desabilitado com o foco no filtro;
  - coluna Kind e datas relativas;
  - Voltar e Avançar (⌘[ ⌘]) com `forwardStack`;
  - `.sheet`, `.confirmationDialog` e `.alert` içados para `BrowserContainerView` usando `model.current`;
  - toolbar agrupada com `ToolbarSpacer`;
  - subtítulo com a seleção;
  - path bar opcional.
- **U4, persistência:**
  - `@SceneStorage` para a sidebar e a última pasta;
  - `TableColumnCustomization` com `customizationID`;
  - sort em `@AppStorage`.
- **U5, login:**
  - `.disabled` durante o SRP e texto "Signing in…";
  - foco na senha após erro;
  - guard de usuário vazio;
  - links "Forgot password" e "Create account" para `account.proton.me`;
  - 2FA com Esc e erro inline (complementa a R7).
- **U6, transferências:**
  - %, velocidade e ETA com taxa suavizada;
  - badge com `.tint`, vermelho só se houver falha;
  - `.help` e "Show Details" nos erros;
  - o popover abre quando um download começa;
  - `.listStyle(.inset)` e contagens nas seções.
- **U7, Settings e Help:**
  - layout flexível;
  - novas opções: pasta padrão de download, abrir Transfers ao iniciar, confirmar trash (`.dialogSuppressionToggle`), concorrência de downloads;
  - menu Help com Issues e Known Limitations;
  - `NSOpenPanel.prompt` = "Download Here".
- **U8, acessibilidade:**
  - labels e values no `Gauge` e nos `ProgressView`;
  - ícone de erro além da cor;
  - conferir VoiceOver e teclado.
- **U9, localização:**
  - `Localizable.xcstrings`;
  - converter as `String`s de `UserFacingError`, `TransferDisplay`, `DriveFormatting` e `.help` para `String(localized:)` / `LocalizedStringResource`;
  - plurais com inflect;
  - tradução completa pt-BR.

Rodar em sequência U1→U2 e U3→U4 (mexem nos mesmos arquivos). U5, U6, U7 e U8 podem rodar em paralelo (⟂). U9 vai por último. Cada view nova ou alterada é conferida com `RenderPreview` em light e dark.

## Fase 5 — Login salvo · branch `feat/f8-5-remember-me` (depende da S2 e da S6)

- `Core/Security/SessionVault.swift`: actor com o blob `RememberedSession` v1 (`uid`, `refreshToken`, `saltedKeyPass`, `username`, `savedAt`).
  - Keychain de data protection, `WhenUnlockedThisDeviceOnly`, sem sincronização.
  - No modo Touch ID: uma KEK num item com `SecAccessControl(.biometryCurrentSet)` e o blob selado em AES-GCM num segundo item; a KEK fica em memória durante a sessão.
- `SessionManager`:
  - `restore(uid:refreshToken:)`;
  - `tokenObserver`, chamado depois do login, de cada refresh e do signOut.
- `AppSession`:
  - separar `finishUnlock(saltedPass:)`;
  - fase `.restoring` disparada no `RootView.task`;
  - qualquer falha no restore ou no unlock → `vault.delete()` e volta ao login;
  - o signOut apaga o item antes de qualquer chamada de rede.
- UI:
  - checkbox "Keep me signed in" no login;
  - toggle "Require Touch ID" e botão "Forget this Mac" em Settings;
  - nome de usuário sempre pré-preenchido.
- Configuração: `DEVELOPMENT_TEAM` e `keychain-access-groups`. Antes, perguntar ao mantenedor o Team ID.
- Docs: ADR-004; atualizar README, SECURITY.md e AUTH.md.
- Testes: `SessionVault` atrás de um protocolo `KeychainStore` com fake em memória. Rotação de token atualiza o blob; signOut apaga; falha no restore apaga.
- Live checks: relançar o app e restaurar a sessão; Touch ID; trocar a senha na web invalida o blob.

## Fase 6 — Funções I · branch `feat/f8-6-files`

1. **F1, tamanhos e datas reais + Get Info (B2).**
   - XAttr decifrado em lote dentro do actor (`Common.Size`, `ModificationTime`);
   - tamanho de pasta continua "—";
   - inspector ⌘I com tamanho, datas, número de revisões, MIME, caminho e badge de assinatura;
   - folha de revisões com download de revisão antiga (reusa `listRevisions` e `getRevision`).
2. **F2, renomear (B5).**
   - Return / F2 / menu de contexto e edição inline;
   - recriptografa o nome com a chave do pai, refaz o hash HMAC e assina;
   - `PUT …/links/{id}/rename`;
   - valida com o `FolderNameValidator`.
3. **F3, mover.**
   - arrastar linhas para uma pasta (reaproveita o encanamento do B10) e Cut/Paste (⌘X/⌘V);
   - re-wrap da passphrase do node para a nova chave do pai, novo nome e hash;
   - `PUT …/links/{id}/move`.
4. **F4, lixeira (B4).**
   - item "Trash" na sidebar;
   - restaurar, excluir definitivamente e esvaziar (⌘⇧⌫);
   - conferir os endpoints de trash do volume/share no SDK C#;
   - undo (⌘Z) logo depois de mover para o lixo.

Cada endpoint novo vira um live check no PR, porque pode cair na allowlist como o upload.

## Fase 7 — Funções II · branch `feat/f8-7-desktop`

1. **F5, Quick Look e abrir (B8).**
   - download para uma pasta temporária no container, `QLPreviewPanel` no Espaço;
   - duplo clique ou "Open" num arquivo → `NSWorkspace.open`;
   - limpar a pasta temporária no signOut e ao sair.
2. **F6, arrastar para o Finder (B9).**
   - `NSFilePromiseProvider` via bridge AppKit;
   - grava pelo caminho atômico com `SafeFilename`.
3. **F7, downloads.**
   - folha de conflito (manter ambos / substituir / pular, com "aplicar a todos"), compartilhada com o upload;
   - retomar depois de relançar: persistir os jobs e pular os blocos já verificados em `.nucleon-part`.
4. **F8, integração com o sistema.**
   - `UNUserNotificationCenter` ao fim de um lote;
   - badge e progresso no Dock;
   - `MenuBarExtra` de transferências;
   - atalhos que faltam: Espaço, Return, ⌘I, ⌘F foca o filtro, type-select.

## Fase 8 — Funções III · branch `feat/f8-8-live`

1. **F9, atualização ao vivo por eventos (B3).**
   - cursor de eventos do volume;
   - busca disparada pela ativação da janela, por navegação e depois de operações próprias, **sem timer de polling**, para respeitar F7 §3.2;
   - invalida só as pastas afetadas.
2. **F10, miniaturas e grade de Fotos (B13).**
   - bloco de thumbnail decifrado com a session key de conteúdo, cache em memória;
   - visualização em ícones e grade no Photos.
3. **F11, nomes reais dos computadores (B7)** via o endpoint de devices.

## Verificação

- Toda fatia termina com `swift test` verde e testes novos, `BuildProject` sem warnings novos e `RenderPreview` light/dark nas views alteradas.
- `code-review` medium no diff de cada fatia. No fim de cada fase, `code-review high` no branch inteiro.
- Fase 3: números do benchmark antes e depois no PR.
- Fase 4: checagem rápida de VoiceOver e navegação só por teclado, via `axiom-accessibility`.
- PR de cada fase: lista de "Live checks for human" (login real, endpoints novos, restore de sessão, Touch ID). Não avanço para uma fase que depende de um live check pendente sem a confirmação do mantenedor.
- Ao final:
  - marcar no `docs/AUDIT-2026-10-04.md` cada item como resolvido, com o link do PR;
  - registrar os itens adiados como issues no GitHub, com confirmação antes de criar;
  - atualizar a contagem de testes no README.
