import os

import imageio


def makeGif(name, files):
    print(name)
    with imageio.get_writer(f"{name}.gif", mode="I", fps=1) as writer:
        for filename in sorted(files):
            image = imageio.imread(filename)
            writer.append_data(image)


rootPath = "./tests/snapshots/stax"
if not os.path.exists(rootPath):
    raise NameError("directory path does not exists")

gifPath = "./tests/gifs/stax"
if not os.path.exists(gifPath):
    os.makedirs(gifPath)

for x in os.listdir(rootPath):
    hasSubDir = False
    for y in os.listdir(os.path.join(rootPath, x)):
        if y.startswith("part"):
            hasSubDir = True
            print(x, y)
            gifFiles = [os.path.join(rootPath, x, y, f) for f in os.listdir(os.path.join(rootPath, x, y))]
            makeGif(os.path.join(gifPath, f"{x}_{y}"), gifFiles)
    if not hasSubDir:
        print(x)
        gifFiles = [os.path.join(rootPath, x, f) for f in os.listdir(os.path.join(rootPath, x))]
        makeGif(os.path.join(gifPath, x), gifFiles)
