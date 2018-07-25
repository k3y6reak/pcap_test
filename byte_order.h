#pragma once

int byte2_order(int byte)
{
    return ((byte&0xff00) >> 8) + ((byte&0x00ff) << 8);
}

int byte4_order(int byte)
{
    return ((byte&0xff000000) >>24) + ((byte&0x00ff0000)>>8) + ((byte&0x0000ff00) <<8) + ((byte&0x000000ff)<<24);
}
