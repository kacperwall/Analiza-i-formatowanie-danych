import csv
from datetime import datetime
import xlrd
import json
from bar_products import show_chart, show_pie_chart

def read_excel():
    workbook = xlrd.open_workbook('produkty.xlsx')
    products = []
    workbook_active = workbook.sheet_by_index(0)
    for index in range(1, workbook_active.nrows):
        row = workbook_active.row(index)
        products.append({
            'category': row[0].value,
            'name': row[1].value,
            'price': row[2].value,
            'qty': row[3].value,
            'shop': row[4].value,
            'date': datetime.strptime(row[5].value, '%d-%m-%Y').date()})
    return products

def read_csv():
    products = []
    with open('products.csv', newline='',
              encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            products.append({
            'category': row['kategoria'],
            'name': row['produkt'],
            'price': row['cena_detaliczna'],
            'qty': row['ilość'],
            'shop': row['sklep'],
            'date': datetime.strptime(row['data'], '%Y-%m-%d').date()})
    return products

def read_json():
    with open('products.json', encoding='utf-8') as json_file:
        json_content = json.load(json_file)
    products = []
    for row in json_content:
        products.append({
            'category': row['category'],
            'name': row['name'],
            'price': row['unit_price'] *4.12,
            'qty': row['quantity'],
            'shop': row['shop'],
            'date': datetime.strptime(row['date_sale'], '%Y-%m-%d').date()
            })
    return products

def prepare_per_name(products):
    sales = {}
    for product in products:
        name = product['name']
        if sales.get(name) is not None:
            sales[name] += float(product['qty'])
        else:
            sales[name] = float(product['qty'])
    return sales
        

products = read_csv()
products_json = read_json()
products_from_excel = read_excel()

products.extend(products_json)
products.extend(products_from_excel)

sales = prepare_per_name(products)
show_pie_chart(sales)

