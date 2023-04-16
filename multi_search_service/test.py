import query

print(query.query_count_per_mi)
query = query.query_count_per_mi
query['aggs']['COMPUTER_NAME']['filter']['term']['host.name.keyword'] = 'DESKTOP-Q04SR1M'
print(query)
