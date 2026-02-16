local urlparse = require("socket.url")
local http = require("socket.http")
local https = require("ssl.https")
local cjson = require("cjson")
local utf8 = require("utf8")
local html_entities = require("htmlEntities")

local item_dir = os.getenv("item_dir")
local warc_file_base = os.getenv("warc_file_base")
local concurrency = tonumber(os.getenv("concurrency"))
local item_type = nil
local item_name = nil
local item_value = nil

local url_count = 0
local tries = 0
local downloaded = {}
local seen_200 = {}
local addedtolist = {}
local abortgrab = false
local killgrab = false
local logged_response = false

local discovered_outlinks = {}
local discovered_items = {}
local discovered_items_sha256 = {}
local bad_items = {}
local ids = {}

local item_patterns = {
  ["^https?://registry%-1%.docker%.io/v2/(.-/manifests/[^/]+)$"] = "image",
  ["^https?://registry%-1%.docker%.io/v2/(.-/blobs/[^/]+)$"] = "blob",
  ["^https?://registry%-1%.docker%.io/v2/(.-)/tags/list$"] = "name",
}

local retry_url = false
local is_initial_url = true

abort_item = function(item)
  abortgrab = true
  --killgrab = true
  if not item then
    item = item_name
  end
  if not bad_items[item] then
    io.stdout:write("Aborting item " .. item .. ".\n")
    io.stdout:flush()
    bad_items[item] = true
  end
end

kill_grab = function(item)
  io.stdout:write("Aborting crawling.\n")
  killgrab = true
end

read_file = function(file)
  if file then
    local f = assert(io.open(file))
    local data = f:read("*all")
    f:close()
    return data
  else
    return ""
  end
end

processed = function(url)
  if downloaded[url] or addedtolist[url] then
    return true
  end
  return false
end

discover_item = function(target, item)
  if target == discovered_items
    and string.match(item, "^[a-z]+:[^/]+:sha256:") then
    target = discovered_items_sha256
  end
  if not target[item] then
print("discovered", item)
    target[item] = true
    return true
  end
  return false
end

find_item = function(url)
  if ids[url] then
    return nil
  end
  local value = nil
  local type_ = nil
  for pattern, name in pairs(item_patterns) do
    value = string.match(url, pattern)
    type_ = name
    if value then
      break
    end
  end
  if value and type_ then
    return {
      ["value"]=value,
      ["type"]=type_
    }
  end
end

set_item = function(url)
  found = find_item(url)
  if found then
    local newcontext = {}
    new_item_type = found["type"]
    if new_item_type == "image" then
      new_item_value = string.gsub(found["value"], "/manifests/", ":")
    elseif new_item_type == "blob" then
      new_item_value = string.gsub(found["value"], "/blobs/", ":")
    elseif new_item_type == "name" then
      new_item_value = found["value"]
    else
      error("Unknown item type " .. new_item_type)
    end
    new_item_name = new_item_type .. ":" .. new_item_value
    if new_item_name ~= item_name then
      ids = {}
      context = newcontext
      context["start_url"] = url
      context["http_stat"] = {}
      context["redo"] = {}
      context["seen_digests"] = {}
      item_value = new_item_value
      item_type = new_item_type
      if item_type == "image" or item_type == "blob" then
        context["image"], context["tag"] = string.match(item_value, "^([^:]+):(.+)$")
        ids[string.lower(context["tag"])] = true
      elseif item_type == "name" then
        context["image"] = item_value
        context["tag"] = nil
      end
      ids[string.lower(item_value)] = true
      ids[string.lower(new_item_name)] = true
      abortgrab = false
      tries = 0
      retry_url = false
      is_initial_url = true
      item_name = new_item_name
      print("Archiving item " .. item_name)
    end
  end
end

allowed = function(url, parenturl)
  local noscheme = string.match(url, "^https?://(.*)$")

  if ids[url]
    or (noscheme and ids[string.lower(noscheme)]) then
    return true
  end

  local skip = false
  for pattern, type_ in pairs(item_patterns) do
    match = string.match(url, pattern)
    if match then
      if type_ == "image" then
        match = string.gsub(match, "/manifests/", ":")
      elseif type_ == "blob" then
        match = string.gsub(match, "/blobs/", ":")
      end
      local new_item = type_ .. ":" .. match
      --[[if new_item == item_name or ids[new_item] then
        return true
      end]]
      if new_item ~= item_name then
print('found new item', new_item)
        discover_item(discovered_items, new_item)
        skip = true
      end
    end
  end
  if skip then
    return false
  end

  for _, pattern in pairs({
    "/blobs/([^/%?&;]+)$",
    "/manifests/([^/%?&;]+)$"
  }) do
    for s in string.gmatch(url, pattern) do
      if ids[string.lower(s)] then
        return true
      end
    end
  end

  return false
end

wget.callbacks.download_child_p = function(urlpos, parent, depth, start_url_parsed, iri, verdict, reason)
  return false
end

wget.callbacks.get_urls = function(file, url, is_css, iri)
  local urls = {}
  local html = nil
  local json = nil
  local new_headers = {}
  local http_stat = context["http_stat"][url]

  downloaded[url] = true

  if abortgrab then
    return {}
  end

  local function check(newurl)
    if allowed(newurl) then
      local headers = {}
      for k, v in pairs(new_headers) do
        headers[k] = v
      end
      headers["Accept"] = headers["Accept"] or "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.artifact.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, */*"
      table.insert(urls, {url=newurl .. "#", headers=headers})
    end
  end

  local function check_with_bearer(newurl, h)
    if h then
      for k, v in pairs(h) do
        new_headers[k] = v
      end
    end
    new_headers["Authorization"]="Bearer " .. context["token"]["token"]
    local result = check(newurl)
    new_headers = {}
    return result
  end

  local function print_digest(message, digest)
    if not context["seen_digests"][digest] then
      print(message .. digest)
      context["seen_digests"][digest] = true
    end
  end

  local function check_next_page(base_url, link)
    if link then
      local next_page = string.match(link[1], "<([^>]+)>;%s*rel=\"next\"")
      if next_page then
        check_with_bearer(urlparse.absolute(base_url, next_page))
      end
    end
  end

  local function check_manifest_digest(digest)
    check_with_bearer(urlparse.absolute(url, "../manifests/" .. digest))
    check_with_bearer(urlparse.absolute(url, "../referrers/" .. digest))
  end

  if status_code == 307
    and string.match(url, "/blobs/") then
    local newurl = urlparse.absolute(url, http_stat["response_headers"]["headers"]["location"][1])
    new_headers["Accept"] = "*/*"
    ids[newurl] = true
    check(newurl)
    new_headers = {}
  end

  if status_code == 200
    and context["realm"]
    and not context["token"]
    and string.sub(url, 1, string.len(context["realm"])) == context["realm"] then
    context["token"] = cjson.decode(read_file(file))
    for redo_url, _ in pairs(context["redo"]) do
      check_with_bearer(redo_url)
    end
    context["redo"] = {}
  end

  if string.match(url, "^https?://registry%-1%.docker%.io/") then
    if status_code == 401
      and context["image"] then
      context["redo"][url] = true
      local newurl = ""
      local header = http_stat["response_headers"]["headers"]["www-authenticate"][1]
      for k, v in string.gmatch(header, "[ ,]([a-z]+)=\"([^\"]+)\"") do
        if k == "realm" then
          newurl = v .. newurl
          context["realm"] = v
        elseif k == "service" or k == "scope" then
          if k == "scope" then
            local image = context["image"]
            if not string.match(image, "/") then
              image = "library/" .. image
            end
            v = "repository:" .. image .. ":pull"
          end
          if string.match(newurl, "%?") then
            newurl = newurl .. "&"
          else
            newurl = newurl .. "?"
          end
          if k ~= "service" then
            v = urlparse.escape(v)
          end
          newurl = newurl .. k .. "=" .. v
        else
          error("Did not recognize key " .. k .. " in header " .. header .. ".")
        end
      end
      ids[newurl] = true
      check(newurl)
    end
    if status_code < 300 then
      html = read_file(file)
      local content_type = http_stat["response_headers"]["headers"]["content-type"][1]
      if content_type then
        content_type = string.match(content_type, "^(.-)%s*;") or content_type
        content_type = string.lower(content_type)
      end
      if string.match(url, "/tags/list") then
        local decoded = cjson.decode(html)
        for _, tag in pairs(decoded["tags"] or {}) do
          discover_item(discovered_items, "image:" .. context["image"] .. ":" .. tag)
        end
        check_next_page(url, http_stat["response_headers"]["headers"]["link"])
      elseif string.match(url, "/referrers/") then
        if content_type == "application/vnd.oci.image.index.v1+json"
          or content_type == "application/vnd.docker.distribution.manifest.list.v2+json"
          or content_type == "application/json" then
          local decoded = cjson.decode(html)
          for _, manifest in pairs(decoded["manifests"] or {}) do
            print_digest("Queuing referrer manifest digest ", manifest["digest"])
            check_manifest_digest(manifest["digest"])
          end
          check_next_page(url, http_stat["response_headers"]["headers"]["link"])
        else
          io.stdout:write("Skipping unsupported referrers content-type " .. tostring(content_type) .. ".\n")
          io.stdout:flush()
        end
      else
        if url == context["start_url"] then
          local digest = http_stat["response_headers"]["headers"]["docker-content-digest"][1]
          if digest and context["tag"] ~= digest then
            print_digest("Queuing own digest ", digest)
            check_manifest_digest(digest)
          end
        end
        if content_type == "application/vnd.oci.image.index.v1+json"
          or content_type == "application/vnd.docker.distribution.manifest.list.v2+json" then
          for _, manifest in pairs(cjson.decode(html)["manifests"]) do
            print_digest("Queuing new digest ", manifest["digest"])
            check_manifest_digest(manifest["digest"])
          end
        elseif content_type == "application/vnd.oci.image.manifest.v1+json"
          or content_type == "application/vnd.docker.distribution.manifest.v2+json" then
          json = cjson.decode(html)
          if json["config"] and json["config"]["digest"] then
            print_digest("Queuing config blob ", json["config"]["digest"])
            check_with_bearer(urlparse.absolute(url, "../blobs/" .. json["config"]["digest"]))
          end
          for _, layer in pairs(json["layers"] or {}) do
            print_digest("Queuing binary blob digest ", layer["digest"])
            check_with_bearer(urlparse.absolute(url, "../blobs/" .. layer["digest"]))
          end
        elseif content_type == "application/vnd.oci.artifact.manifest.v1+json" then
          json = cjson.decode(html)
          for _, blob in pairs(json["blobs"] or {}) do
            print_digest("Queuing artifact blob digest ", blob["digest"])
            check_with_bearer(urlparse.absolute(url, "../blobs/" .. blob["digest"]))
          end
        else
          io.stdout:write("Unrecognized content-type " .. content_type .. ".")
          io.stdout:flush()
          abort_item()
          return {}
        end
      end
    end
  end

  return urls
end

calculate_sum = function(algorithm, filepath)
  local process = io.popen(algorithm .. "sum " .. filepath, "r")
  local d = process:read("*l")
  process:close()
  return string.match(d, "([^%s]+)")
end

wget.callbacks.write_to_warc = function(url, http_stat)
  status_code = http_stat["statcode"]
  set_item(url["url"])
  url_count = url_count + 1
  io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. " \n")
  io.stdout:flush()
  logged_response = true
  if not item_name then
    error("No item name found.")
  end
  is_initial_url = false
  if http_stat["statcode"] == 401 then
    -- still mark as correct, handle in get_urls
    io.stdout:write("Not writing this 401 to WARC.\n")
    io.stdout:flush()
    retry_url = false
    tries = 0
    return false
  end
  if string.match(url["url"], "/referrers/")
    and (
      http_stat["statcode"] == 400
      or http_stat["statcode"] == 404
      or http_stat["statcode"] == 405
    ) then
    io.stdout:write("Not writing nonexisting /referrers/ to WARC.\n")
    io.stdout:flush()
    retry_url = false
    tries = 0
    return false
  end
  if http_stat["statcode"] ~= 200
    and http_stat["statcode"] ~= 307 then
    io.stdout:write("Bad status code.\n")
    io.stdout:flush()
    retry_url = true
    return false
  end
  if http_stat["len"] == 0
    and http_stat["statcode"] < 300 then
    io.stdout:write("Found body size 0.\n")
    io.stdout:flush()
    retry_url = true
    return false
  end
  if http_stat["statcode"] == 200 then
    algorithm = nil
    hash = nil
    if item_type == "image" or item_type == "blob" then
      algorithm, hash = string.match(context["tag"], "^(sha256):(.+)$")
    end
    if not algorithm then
      local etag = http_stat["response_headers"]["headers"]["etag"]
      if etag then
        local algorithm, hash = string.match(etag[1], "^\"?([^:]-):(.-)\"?$")
        if not algorithm or not hash then
          algorithm = "md5"
          hash = string.match(etag[1], "^\"?(.-)\"?$")
        end
      end
    end
    if algorithm and hash then
      local calculated = calculate_sum(algorithm, http_stat["local_file"])
      if calculated == hash then
        print("Sums match.")
      end
    end
  end
  if abortgrab then
    print("Not writing to WARC.")
    return false
  end
  retry_url = false
  tries = 0
  return true
end

wget.callbacks.httploop_result = function(url, err, http_stat)
  status_code = http_stat["statcode"]

  context["http_stat"][url["url"]] = cjson.decode(cjson.encode(http_stat))

  if not logged_response then
    url_count = url_count + 1
    io.stdout:write(url_count .. "=" .. status_code .. " " .. url["url"] .. " \n")
    io.stdout:flush()
  end
  logged_response = false

  if killgrab then
    return wget.actions.ABORT
  end

  set_item(url["url"])
  if not item_name then
    error("No item name found.")
  end

  if abortgrab then
    abort_item()
    return wget.actions.EXIT
  end

  if status_code == 0 or retry_url then
    io.stdout:write("Server returned bad response. ")
    io.stdout:flush()
    tries = tries + 1
    local maxtries = 5
    if tries > maxtries then
      io.stdout:write(" Skipping.\n")
      io.stdout:flush()
      tries = 0
      abort_item()
      return wget.actions.EXIT
    end
    local sleep_time = math.random(
      math.floor(math.pow(2, tries-0.5)),
      math.floor(math.pow(2, tries))
    )
    io.stdout:write("Sleeping " .. sleep_time .. " seconds.\n")
    io.stdout:flush()
    os.execute("sleep " .. sleep_time)
    return wget.actions.CONTINUE
  else
    if status_code == 200 then
      if not seen_200[url["url"]] then
        seen_200[url["url"]] = 0
      end
      seen_200[url["url"]] = seen_200[url["url"]] + 1
    end
    downloaded[url["url"]] = true
  end

  if status_code >= 300 and status_code <= 399 then
    local newloc = urlparse.absolute(url["url"], http_stat["newloc"])
    if status_code == 307 then
      --ids[newloc] = true
      return wget.actions.EXIT
    elseif processed(newloc) or not allowed(newloc, url["url"]) then
      tries = 0
      return wget.actions.EXIT
    end
  end

  tries = 0

  return wget.actions.NOTHING
end

wget.callbacks.finish = function(start_time, end_time, wall_time, numurls, total_downloaded_bytes, total_download_time)
  local function submit_backfeed(items, key)
    local tries = 0
    local maxtries = 5
    while tries < maxtries do
      if killgrab then
        return false
      end
      local body, code, headers, status = http.request(
        "https://legacy-api.arpa.li/backfeed/legacy/" .. key,
        items .. "\0"
      )
      if code == 200 and body ~= nil and cjson.decode(body)["status_code"] == 200 then
        io.stdout:write(string.match(body, "^(.-)%s*$") .. "\n")
        io.stdout:flush()
        return nil
      end
      io.stdout:write("Failed to submit discovered URLs." .. tostring(code) .. tostring(body) .. "\n")
      io.stdout:flush()
      os.execute("sleep " .. math.floor(math.pow(2, tries)))
      tries = tries + 1
    end
    kill_grab()
    error()
  end

  local file = io.open(item_dir .. "/" .. warc_file_base .. "_bad-items.txt", "w")
  for url, _ in pairs(bad_items) do
    file:write(url .. "\n")
  end
  file:close()
  for key, data in pairs({
    --["docker-"] = discovered_items,
    --["urls-"] = discovered_outlinks,
    --["docker-hashes-?skipbloom=1"] = discovered_items_sha256
  }) do
    print("queuing for", string.match(key, "^(.+)%-"))
    local items = nil
    local count = 0
    for item, _ in pairs(data) do
      print("found item", item)
      if items == nil then
        items = item
      else
        items = items .. "\0" .. item
      end
      count = count + 1
      if count == 1000 then
        submit_backfeed(items, key)
        items = nil
        count = 0
      end
    end
    if items ~= nil then
      submit_backfeed(items, key)
    end
  end
end

wget.callbacks.before_exit = function(exit_status, exit_status_string)
  if killgrab then
    return wget.exits.IO_FAIL
  end
  if abortgrab then
    abort_item()
  end
  return exit_status
end
