import random
import math

avg_mean_residence_import = random.randint(1,5)
avg_max_residence_import = random.randint(1,6)
total_packet_count_import = 6 * 1000
total_packet_dest_import = {'Dest-1(R4)':1114 , 'Dest-2(R7)':828, 'Dest-3(R6)':748}
total_packet_next_hop_import = {'R102': 847, 'R105': 1223, 'R104': 533 ,'R106': 330 ,'R107': 364}