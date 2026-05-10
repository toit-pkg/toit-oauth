// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import oauth show LocalStorage

/**
A $LocalStorage backed by an in-memory map for testing.
*/
class TestLocalStorage implements LocalStorage:
  value_/any := null

  constructor --initial/any=null:
    value_ = initial

  has-auth -> bool: return value_ != null
  get-auth -> any?: return value_
  set-auth value/any -> none: value_ = value
  remove-auth -> none: value_ = null
