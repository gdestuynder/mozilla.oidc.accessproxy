-- Lua reference for nginx: https://github.com/openresty/lua-nginx-module
-- Lua reference for jwt: https://github.com/SkyLothar/lua-resty-jwt/
-- Lua reference for openidc: https://github.com/zmartzone/lua-resty-openidc

-- Libraries
local oidc = require("resty.openidc")
local cjson = require( "cjson" )
local cjson_s = require "cjson.safe"
local http = require "resty.http"
local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"
local auth_header = ngx.var.http_Authorization

-- local-globals ;-)
local allowed_group = os.getenv('allowed_group')
local jwt_token = nil

-- Functions we need
local function get_url_json(url)
  local json, err
  local httpc = http.new()
  local res, error = httpc:request_uri(url)
  if not res then
    err = "accessing url (" .. url .. ") failed: " .. error
  else
    json = cjson_s.decode(res.body)
  end

  return json, err
end

local function split_by_chunk(text, chunkSize)
  local s = {}
  for i = 1, #text, chunkSize do
    s[#s + 1] = text:sub(i, i + chunkSize - 1)
  end
  return s
end

local function base64_url_decode(input)
  local reminder = #input % 4
  if reminder > 0 then
    local padlen = 4 - reminder
    input = input .. string.rep('=', padlen)
  end
  input = input:gsub('-', '+'):gsub('_', '/')
  return ngx.decode_base64(input)
end

local function pem_from_x5c(x5c)
  local chunks = split_by_chunk(ngx.encode_base64(base64_url_decode(x5c[1])), 64)
  local pem = "-----BEGIN CERTIFICATE-----\n" ..
      table.concat(chunks, "\n") ..
      "\n-----END CERTIFICATE-----"
  return pem
end

-- Options must be present
if not opts then
  ngx.log(ngx.ERR, "no configuration found")
end

-- Verify API-style authorization first
if auth_header then
  _, _, jwt_token = string.find(auth_header, "Bearer%s+(.+)")

  local discovery, err = get_url_json(opts.discovery)
  local issuer = discovery.issuer
  local jwks, err = get_url_json(discovery.jwks_uri)
  -- Remember, lua tables starts at 1, not 0.
  local jwt_pub_key = pem_from_x5c(jwks.keys[1].x5c)

  -- Actual JWT verification
  local claimspec = {
    validators.set_system_leeway(60), -- seconds
    exp = validators.is_not_expired(),
    iat = validators.is_not_before(),
    iss = validators.equals_any_of({ issuer }),
    aud = validators.equals_any_of({ opts.client_id } ), -- The client id / our audience, this is as important as `iss`
  }
  if allowed_group then
    claimspec["https://sso.mozilla.com/claim/groups"] = validators.opt_matches(allowed_group) -- Mozilla group structure
  end

  ngx.header.content_type = "application/json; charset=utf-8"
  if not jwt_pub_key then
    ngx.log(ngx.WARN, "no jwt public key, make sure you have set jwt_pub_key")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("{\"error\": \"server misconfigured\"}")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)

  elseif not jwt_token then
    ngx.log(ngx.WARN, "no JWT token found")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("{\"error\": \"missing JWT token or Authorization header\"}")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)

  else
    local jwt_obj = jwt:verify(jwt_pub_key, jwt_token, claimspec)
    if not jwt_obj.verified then
      ngx.log(ngx.ERR, cjson.encode(jwt_obj))
      ngx.log(ngx.WARN, "JWT verification failure: " .. jwt_obj.reason)
      ngx.status = ngx.HTTP_UNAUTHORIZED
      ngx.say("{\"error\": \"" .. jwt_obj.reason .. "\"}")
      ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.NOTICE, "JWT token verified successfully")
    ngx.req.set_header("REMOTE_USER_SUB", jwt_obj.sub)
    ngx.req.set_header("X-Forwarded-User-Subject", jwt_obj.sub)
    -- For dev only
    -- ngx.say(cjson.encode(jwt_obj));
    --ngx.log(ngx.ERR, cjson.encode(jwt_obj))
    -- ngx.exit(ngx.HTTP_OK)
    -- pass through
  end
else
  -- Verify the human-style authorization now
  -- Authenticate with lua-resty-openidc if necessary (this will return quickly if no authentication is necessary)
  local res, err, url, session = oidc.authenticate(opts)

  -- Check if authentication succeeded, otherwise kick the user out
  if err then
    if session ~= nil then
      session:destroy()
    end
    ngx.redirect(opts.logout_path)
  end
  -- If you want all claims as headers, use this
  -- local function build_headers(t, name)
  --   for k,v in pairs(t) do
  --     -- unpack tables
  --     if type(v) == "table" then
  --       local j = cjson.encode(v)
  --       ngx.req.set_header("OIDC_CLAIM_"..name..k, j)
  --     else
  --       ngx.req.set_header("OIDC_CLAIM_"..name..k, tostring(v))
  --     end
  --   end
  -- end

  -- build_headers(session.data.id_token, "ID_TOKEN_")
  -- build_headers(session.data.user, "USER_PROFILE_")

  -- Set most useful headers with user info and OIDC claims for the underlaying web application to use
  -- These header names are voluntarily similar to Apaches mod_auth_openidc and other modules,
  -- but may of course be modified
  -- NOTE: You should use the REMOTE_USER_SUB as identifier as REMOTE_USER (email) is not a real user id
  ngx.req.set_header("REMOTE_USER", session.data.user.email)
  ngx.req.set_header("REMOTE_USER_SUB", session.data.user.sub)
  ngx.req.set_header("X-Forwarded-User", session.data.user.email)
  ngx.req.set_header("X-Forwarded-User-Subject", session.data.user.sub)
  ngx.req.set_header("OIDC_CLAIM_ACCESS_TOKEN", session.data.access_token)
  ngx.req.set_header("OIDC_CLAIM_ID_TOKEN", session.data.enc_id_token)
  ngx.req.set_header("via",session.data.user.email)

  -- Flatten groups for apps that won't read JSON
  local grps = false
  local usergrp = ""
  if session.data.user.groups then
      usergrp = session.data.user.groups
  elseif session.data.user['https://sso.mozilla.com/claim/groups'] then
      usergrp = session.data.user['https://sso.mozilla.com/claim/groups']
  end
  if usergrp ~= "" and usergrp ~= nil then
      for k,v in pairs(usergrp) do
        grps = (grps and grps.."|"..v) or v  -- If grps is false, set grps to v, otherwise append "|v" to grps
      end
      ngx.req.set_header("X-Forwarded-Groups", grps)
  end

  -- Access control: only allow specific users in (this is optional, without it all authenticated users are allowed in)
  if allowed_group then
      local authorized = false
      for _, group in ipairs(usergrp) do
          if group == allowed_group then
              authorized = true
          end
      end

      if not authorized then
        ngx.log(ngx.ERR, "Permission denied for user")
        if session ~= nil then
          session:destroy()
        end
          ngx.redirect(opts.logout_path)
      end
  end
end
