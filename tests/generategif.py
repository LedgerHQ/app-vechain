import imageio
import os

def makeGif(name,files):
    print(name)
    with imageio.get_writer(f"{name}.gif", mode='I',fps=1) as writer:
        for filename in sorted(files):
            image = imageio.imread(filename)
            writer.append_data(image)
rootPath = './tests/snapshots/stax'
if not os.path.exists(rootPath):
    raise NameError('directory path does not exists')
gifPath = './tests/gifs/stax'
if not os.path.exists(gifPath):
    os.makedirs(gifPath)
for x in os.listdir(rootPath):
    hasSubDir = False
    for y in os.listdir(os.path.join(rootPath,x)):
        if (y.startswith('part')):
            hasSubDir = True
            print(x,y)
            makeGif(os.path.join(gifPath,f"{x}_{y}"),list(map(
                lambda f: os.path.join(rootPath,x,y,f),
                os.listdir(os.path.join(rootPath,x,y))
            )))
    if not hasSubDir:
        print(x)
        makeGif(os.path.join(gifPath,x),list(map(
                lambda f: os.path.join(rootPath,x,f),
                os.listdir(os.path.join(rootPath,x))
            )))
    
