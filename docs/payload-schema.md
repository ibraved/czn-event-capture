# Payload schema

The JSON payload the addon POSTs to `/api/events/submissions`:

```jsonc
{
  "captured_at": "2026-04-22T...",
  "user_id":  "300000691488",
  "world_id": "world_live_global",

  "events": [
    {
      "define_id":     "remnants_boss_penalty_002",
      "rank":          38903,
      "rank_percent":  66.73,
      "reward_count":  1,
      "entities": {
        "remnants_boss_s02_01": {
          "list_id":         "remnants_boss_s02_01",
          "best_score":      217367,
          "star_count":      1,
          "deployed_heroes": [30075, 1033, 1003]
        }
      }
    }
  ],

  "attempts": [
    {
      "stage_id":         6000001,
      "stage_type":       "STAGE_TYPE_BOSS",
      "captured_at":      "...",
      "stage_chars":      [ /* per-character build: level, ascend, limit_break,
                              friendship_exp, potential_node_ids, piece_set_options,
                              equipped_pieces, skill_ev_add, derived status */ ],
      "stage_supporters": [ /* partner cards deployed */ ],
      "deck":             [ /* cards played with r_spark references */ ],
      "mvp":              "30075",
      "player":           { "ep": 260, "status": { ... } },
      "return_info":      { /* score log, etc. */ }
    }
  ],

  "user_state": {
    "characters":             [ /* per-character progression */ ],
    "savedata":               [ /* all saved builds */ ],
    "savedata_slot_entities": { /* which build is in which slot per character */ },
    "savedata_teams":         { /* saved team presets */ },
    "team_presets":           [ /* user-defined team slots */ ],
    "teams":                  [ ],
    "archive_supporters":     [ /* unlocked partner cards */ ],
    "card_archive":           [ /* unlocked cards */ ]
  }
}
```

> The field names `stage_supporters` and `archive_supporters` come from the game's wire format and are preserved verbatim in the payload. The human-facing term throughout this repo is "partner card".
