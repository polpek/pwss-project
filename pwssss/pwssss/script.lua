-- skrypt dostaje request http "GET /Hello HTTP/1.1" w zmiennej globalnej arg1

function handle_request(request)

    local _, _, method, path = request:find("(%a+) (/[^%s]+) HTTP/[%d%.]+")
    if not method or not path then
      return "Blad wykonywaniu skryptu LUA"
    end  
    return "wykonano"
  end



-- print(arg1)
print(handle_request(arg1))
return "asdasdaasdadadasdsdasdsd"