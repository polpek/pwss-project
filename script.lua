-- skrypt dostaje request http "GET /Hello HTTP/1.1" w zmiennej globalnej arg1

function sum_variables(request)
    local _, _, query_string = string.find(request, "GET /[^%s]+%?([^%s]+) HTTP/[%d%.]+")
    local sum = 0
    for key, value in string.gmatch(query_string, "(%w+)=(%w+)&?") do
        print(value)
        sum = sum + value
    end
    return sum
end

return sum_variables(arg1)
