# Locale helpers for the czn-event-capture tool. Dot-sourced by run.ps1.
#
# Resolve-Locale picks a locale from, in order:
#   1. -Override, when set and valid
#   2. Windows system culture (Get-Culture): zh-Hant/zh-TW -> zht, zh-* -> zh
#      (falls back to en), ja-* -> ja, ko-* -> ko, otherwise en
#   3. "en"
#
# T <id> returns the current locale's string, falling back to English. If a
# key is missing from English too, the id is returned as-is so the missing
# key is obvious instead of silently empty.

function Resolve-Locale {
  [CmdletBinding()]
  param([string]$Override)
  if ($Override -and @('en', 'ko', 'ja', 'zht') -contains $Override) {
    $script:CurrentLocale = $Override
    return $Override
  }
  $culture = ''
  try { $culture = (Get-Culture).Name } catch {}
  $lower = $culture.ToLower()
  $resolved = 'en'
  if ($lower -like 'zh-hant*' -or $lower -like 'zh-tw*' -or $lower -like 'zh-hk*' -or $lower -like 'zh-mo*') {
    $resolved = 'zht'
  } elseif ($lower -like 'ja*') {
    $resolved = 'ja'
  } elseif ($lower -like 'ko*') {
    $resolved = 'ko'
  }
  $script:CurrentLocale = $resolved
  return $resolved
}

# Central string table. Keep keys in dotted namespace; grouped by source file.
$script:LOCALE_TABLE = @{
  'en' = @{
    # ----- pair-mode
    'pair.header'         = 'Device pairing'
    'pair.codeHeading'    = '  Your pairing code:'
    'pair.enterAt'        = '  Enter this code at {0}/events/submit'
    'pair.thenAuthorize'  = "  Sign in, click 'Pair this computer', paste the code, hit Authorize."
    'pair.waiting'        = '  Waiting for you to authorize in the browser...'
    'pair.requestFailed'  = 'Server did not return a pairing code.'
    'pair.expired'        = 'Code expired before authorization. Run the tool again to generate a new one.'
    'pair.success'        = ' [OK] Paired successfully. Token saved to {0}'
    'pair.timeout'        = 'Timed out after 10 minutes waiting for authorization.'
    'pair.unexpected'     = 'Unexpected status response: {0}'
    'pair.unreachable'    = 'Could not reach server: {0}'
    'pair.closePrompt'    = 'Press Enter to close'

    # ----- capture flow (highest-visibility strings)
    'capture.liveBanner' = 'Capture is LIVE. Now do this in the game:'
  }
  'ko' = @{
    'pair.header'         = '기기 페어링'
    'pair.codeHeading'    = '  페어링 코드:'
    'pair.enterAt'        = '  이 코드를 {0}/events/submit 에 입력하세요.'
    'pair.thenAuthorize'  = "  로그인 후 'Pair this computer'를 클릭하고 코드를 붙여넣은 다음 Authorize를 누르세요."
    'pair.waiting'        = '  브라우저에서 인증을 기다리는 중...'
    'pair.requestFailed'  = '서버가 페어링 코드를 반환하지 않았습니다.'
    'pair.expired'        = '인증 전에 코드가 만료되었습니다. 도구를 다시 실행하여 새 코드를 생성하세요.'
    'pair.success'        = ' [OK] 페어링 성공. 토큰을 {0}에 저장했습니다.'
    'pair.timeout'        = '10분 동안 인증을 기다린 후 시간이 초과되었습니다.'
    'pair.unexpected'     = '예상치 못한 상태 응답: {0}'
    'pair.unreachable'    = '서버에 접속할 수 없습니다: {0}'
    'pair.closePrompt'    = '종료하려면 Enter 키를 누르세요'

    'capture.liveBanner'       = '캡처가 진행 중입니다. 이제 게임에서 다음을 수행하세요:'
  }
  'ja' = @{
    'pair.header'         = 'デバイスのペアリング'
    'pair.codeHeading'    = '  ペアリングコード:'
    'pair.enterAt'        = '  このコードを {0}/events/submit で入力してください。'
    'pair.thenAuthorize'  = "  サインイン後、'Pair this computer' をクリックしてコードを貼り付け、Authorize を押します。"
    'pair.waiting'        = '  ブラウザでの認証を待機中...'
    'pair.requestFailed'  = 'サーバーがペアリングコードを返しませんでした。'
    'pair.expired'        = '認証前にコードが失効しました。ツールを再実行して新しいコードを生成してください。'
    'pair.success'        = ' [OK] ペアリングに成功しました。トークンを {0} に保存しました。'
    'pair.timeout'        = '認証を 10 分間待機しましたがタイムアウトしました。'
    'pair.unexpected'     = '予期しないステータス応答: {0}'
    'pair.unreachable'    = 'サーバーに到達できません: {0}'
    'pair.closePrompt'    = '終了するには Enter を押してください'

    'capture.liveBanner' = 'キャプチャが開始されました。ゲームで以下を行ってください:'
  }
  'zht' = @{
    'pair.header'         = '裝置配對'
    'pair.codeHeading'    = '  您的配對碼：'
    'pair.enterAt'        = '  請在 {0}/events/submit 輸入此配對碼。'
    'pair.thenAuthorize'  = "  登入後點選「Pair this computer」，貼上配對碼並按下 Authorize。"
    'pair.waiting'        = '  等待您在瀏覽器中完成授權...'
    'pair.requestFailed'  = '伺服器未回傳配對碼。'
    'pair.expired'        = '授權前配對碼已過期。請重新執行工具以產生新配對碼。'
    'pair.success'        = ' [OK] 配對成功。權杖已儲存至 {0}。'
    'pair.timeout'        = '等待授權超過 10 分鐘，已逾時。'
    'pair.unexpected'     = '意外的狀態回應：{0}'
    'pair.unreachable'    = '無法連線到伺服器：{0}'
    'pair.closePrompt'    = '按 Enter 關閉'

    'capture.liveBanner' = '擷取已開始。請在遊戲中執行下列步驟：'
  }
}

function T {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$Id)
  $loc = $script:CurrentLocale
  if (-not $loc) { $loc = 'en' }
  $bucket = $script:LOCALE_TABLE[$loc]
  if ($bucket -and $bucket.ContainsKey($Id)) { return $bucket[$Id] }
  $fallback = $script:LOCALE_TABLE['en']
  if ($fallback -and $fallback.ContainsKey($Id)) { return $fallback[$Id] }
  return $Id
}
