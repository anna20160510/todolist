import pygame as pg
import random
import math
import sys # 建議加入 sys 以便在需要時能安全退出

# --- 全域常數與設定 ---
STATE_SEEKING_FOOD = 0
STATE_RETURNING_HOME = 1

# 設定參數
WIDTH, HEIGHT = 800, 600
ANT_SPEED = 2
FOOD_AMOUNT = 8
ANT_AMOUNT = 20
FPS = 60
ANT_INIT_VELOCITY_FACTOR = 0.3
ANT_SMOOTHING_FACTOR = 0.05 # 慣性因子

HOME_POSITION = (WIDTH // 2, HEIGHT // 2)
HOME_RADIUS = 20  # 到家判定半徑
NEST_COLOR = (205, 133, 63)

food_list = list()

class Ant(pg.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image_white = pg.Surface((10, 10)) # 保存原始白色圖像
        self.image_white.fill((255, 255, 255))
        self.image_yellow = pg.Surface((10, 10)) # 保存返家黃色圖像
        self.image_yellow.fill((255, 255, 0)) # 黃色

        self.image = self.image_white.copy() # 當前使用的圖像
        self.rect = self.image.get_rect()
        
        spawn_margin = 20
        self.rect.center = (random.randint(spawn_margin, WIDTH - spawn_margin),
                            random.randint(spawn_margin, HEIGHT - spawn_margin))

        initial_angle = random.uniform(0, 2 * math.pi)
        initial_speed = ANT_SPEED * ANT_INIT_VELOCITY_FACTOR
        self.velocity_x = math.cos(initial_angle) * initial_speed
        self.velocity_y = math.sin(initial_angle) * initial_speed

        self.smoothing_factor = ANT_SMOOTHING_FACTOR
        self.ANT_directionx = 0
        self.ANT_directiony = 0

        self.state = STATE_SEEKING_FOOD # 初始狀態為尋找食物

    def calculate_target_direction(self):
        self.Total_x = 0 
        self.Total_y = 0
        ant_center_x = self.rect.centerx
        ant_center_y = self.rect.centery

        if self.state == STATE_SEEKING_FOOD:
            if not food_list: # 檢查 food_list 是否為空
                self.ANT_directionx = random.uniform(-1, 1)
                self.ANT_directiony = random.uniform(-1, 1)
            else:
                for food_coords in food_list:
                    distance = math.sqrt((food_coords[0] - ant_center_x) ** 2 + (food_coords[1] - ant_center_y) ** 2)
                    if distance < 1:
                        if distance == 0:
                            self.Total_x += random.uniform(-0.01, 0.01)
                            self.Total_y += random.uniform(-0.01, 0.01)
                        continue
                    weight = 1 / (distance ** 2)
                    self.Total_x += (food_coords[0] - ant_center_x) * weight
                    self.Total_y += (food_coords[1] - ant_center_y) * weight
                self.ANT_directionx = self.Total_x
                self.ANT_directiony = self.Total_y

        elif self.state == STATE_RETURNING_HOME:
            home_x, home_y = HOME_POSITION
            dx_home = home_x - ant_center_x
            dy_home = home_y - ant_center_y
            dist_to_home = math.hypot(dx_home, dy_home)

            if dist_to_home < HOME_RADIUS: # 到達家附近
                self.state = STATE_SEEKING_FOOD
                # 到家後，下一幀會重新尋找食物。本幀給一個小的隨機方向。
                self.ANT_directionx = random.uniform(-0.1, 0.1) 
                self.ANT_directiony = random.uniform(-0.1, 0.1)
            else:
                self.ANT_directionx = dx_home
                self.ANT_directiony = dy_home

    def update_velocity(self):
        self.calculate_target_direction()
        target_vx = 0
        target_vy = 0

        if self.ANT_directionx == 0 and self.ANT_directiony == 0:
            # 如果目標方向為零 (例如，剛到家切換狀態，或無食物時的隨機方向恰好為0)
            # 給予微小擾動，避免速度完全降為0後無法再啟動（除非這是期望行為）
            self.ANT_directionx = random.uniform(-0.05, 0.05) # 更小的擾動
            self.ANT_directiony = random.uniform(-0.05, 0.05)
            if self.ANT_directionx == 0 and self.ANT_directiony == 0:
                 self.ANT_directionx = 0.01

        norm_direction = math.sqrt(self.ANT_directionx ** 2 + self.ANT_directiony ** 2)
        if norm_direction == 0:
            target_vx = 0
            target_vy = 0
        else:
            target_vx = (self.ANT_directionx / norm_direction) * ANT_SPEED
            target_vy = (self.ANT_directiony / norm_direction) * ANT_SPEED
        
        self.velocity_x = self.velocity_x * (1 - self.smoothing_factor) + target_vx * self.smoothing_factor
        self.velocity_y = self.velocity_y * (1 - self.smoothing_factor) + target_vy * self.smoothing_factor

        current_actual_speed = math.sqrt(self.velocity_x**2 + self.velocity_y**2)
        if current_actual_speed > ANT_SPEED:
            self.velocity_x = (self.velocity_x / current_actual_speed) * ANT_SPEED
            self.velocity_y = (self.velocity_y / current_actual_speed) * ANT_SPEED

    def update(self):
        self.update_velocity()
        
        self.rect.x += self.velocity_x
        self.rect.y += self.velocity_y

        # 更新螞蟻顏色根據狀態
        if self.state == STATE_SEEKING_FOOD:
            if self.image is not self.image_white:
                self.image = self.image_white.copy()
        elif self.state == STATE_RETURNING_HOME:
            if self.image is not self.image_yellow:
                self.image = self.image_yellow.copy()

        # 邊界反彈處理
        bounce_factor = -0.5
        if self.rect.left < 0:
            self.rect.left = 0
            if self.velocity_x < 0: self.velocity_x *= bounce_factor
        elif self.rect.right > WIDTH:
            self.rect.right = WIDTH
            if self.velocity_x > 0: self.velocity_x *= bounce_factor
        
        if self.rect.top < 0:
            self.rect.top = 0
            if self.velocity_y < 0: self.velocity_y *= bounce_factor
        elif self.rect.bottom > HEIGHT:
            self.rect.bottom = HEIGHT
            if self.velocity_y > 0: self.velocity_y *= bounce_factor


class Food(pg.sprite.Sprite):
    def __init__(self,center_pos = None):
        super().__init__()
        self.image = pg.Surface((10, 10))
        self.image.fill((255, 0, 0)) # 紅色
        self.rect = self.image.get_rect()

        if center_pos:
            self.rect.center = center_pos
        else:
            margin = 100
            self.rect.center = (random.randint(margin, WIDTH - margin), random.randint(margin, HEIGHT - margin))
        
        # --- 修改：確保 food_list 是全域的，並加入 ---
        global food_list
        food_list.append(list(self.rect.center))

# --- 主遊戲函式 ---
def main():
    """這個函式包含了所有 Pygame 的啟動和執行邏輯。"""
    pg.init() # 初始化
    
    global food_list # 宣告我們要使用全域的 food_list
    food_list = [] # 每次啟動時清空列表，確保重新開始

    screen = pg.display.set_mode((WIDTH, HEIGHT))
    pg.display.set_caption("Ant AI Simulation")
    clock = pg.time.Clock()

    all_sprites = pg.sprite.Group()
    ants = pg.sprite.Group()
    foods = pg.sprite.Group()

    # 建立食物
    for _ in range(FOOD_AMOUNT):
        food_item = Food()
        all_sprites.add(food_item)
        foods.add(food_item)

    # 建立螞蟻
    for _ in range(ANT_AMOUNT): 
        ant_sprite = Ant()
        all_sprites.add(ant_sprite)
        ants.add(ant_sprite)

    # 遊戲主迴圈
    running = True
    while running:
        clock.tick(FPS)
        for event in pg.event.get():
            if event.type == pg.QUIT:
                running = False

            elif event.type == pg.MOUSEBUTTONDOWN:
                if event.button == 1:
                    mouse_pos = event.pos

                new_food_item = Food(center_pos = mouse_pos) 
                all_sprites.add(new_food_item)
                foods.add(new_food_item)


        # 碰撞處理
        picked_foods_dict = pg.sprite.groupcollide(foods, ants, True, False)
        for food_collided, colliding_ants_list in picked_foods_dict.items():
            center_coords_to_remove = list(food_collided.rect.center)
            if center_coords_to_remove in food_list:
                food_list.remove(center_coords_to_remove)
                # print(food_list)
            
            for ant_involved in colliding_ants_list:
                if isinstance(ant_involved, Ant):
                    ant_involved.state = STATE_RETURNING_HOME

            #new_food = Food()
            #all_sprites.add(new_food)
            #foods.add(new_food)

        if len(food_list) == 0:
            for i in range(2):
                new_food = Food()
                all_sprites.add(new_food)
                foods.add(new_food)            

        # 更新所有精靈
        all_sprites.update()

        # 繪製畫面
        screen.fill((0, 0, 0)) 
    
        pg.draw.circle(screen, NEST_COLOR, HOME_POSITION, HOME_RADIUS)

        # 繪製所有精靈
        all_sprites.draw(screen)
        
        # 更新顯示
        pg.display.flip()

    pg.quit() # 結束 Pygame
    sys.exit()

if __name__ == "__main__":
    main()