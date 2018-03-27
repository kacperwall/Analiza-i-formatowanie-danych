import matplotlib.pyplot as plt

COLORS = ('b', 'g', 'c', 'm', 'y', 'k', 'w')
def color_rotator(order):
    return COLORS[order % len(COLORS)]

def show_chart(sales):
    bars_order = [i for i in range(len(sales.keys()))]
    bars_heights = sales.values()
    labels = list(sales.keys())

    plt.xticks(bars_order, sales.keys())

    product_bars = plt.bar(bars_order, bars_heights)
    for i, product_bar in enumerate(product_bars):
        product_bar.set_color(color_rotator(i))

    plt.title('Ile sprzedano')
    plt.show()

def show_pie_chart(sales):
    labels = list(sales.keys())
    sizes = list(sales.values())
    fig, ax = plt.subplots()
    ax.pie(sizes, labels = labels)
    plt.show()
