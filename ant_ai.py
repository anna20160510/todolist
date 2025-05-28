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
FOOD_AMOUNT = 15
FPS = 60
ANT_INIT_VELOCITY_FACTOR = 0.3
ANT_SMOOTHING_FACTOR = 0.05 # 慣性因子

HOME_POSITION = (WIDTH // 2, HEIGHT // 2)
HOME_RADIUS = 20  # 到達家判定半徑 (像素)

# 全域變數 (只保留需要跨函式共用的，或者在主函式內處理)
food_list = list()

# 螞蟻類 (Ant Class - 您的程式碼，保持不變)
class Ant(pg.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image_original_white = pg.Surface((10, 10)) # 保存原始白色圖像
        self.image_original_white.fill((255, 255, 255))
        self.image_original_yellow = pg.Surface((10, 10)) # 保存返家黃色圖像
        self.image_original_yellow.fill((255, 255, 0)) # 黃色

        self.image = self.image_original_white.copy() # 當前使用的圖像
        self.rect = self.image.get_rect()
        
        # 將螞蟻出生點改為家的位置
        self.rect.center = HOME_POSITION

        initial_angle = random.uniform(0, 2 * math.pi)
        initial_speed = ANT_SPEED * ANT_INIT_VELOCITY_FACTOR
        self.velocity_x = math.cos(initial_angle) * initial_speed
        self.velocity_y = math.sin(initial_angle) * initial_speed

        self.smoothing_factor = ANT_SMOOTHING_FACTOR
        self.ANT_directionx = 0
        self.ANT_directiony = 0

        self.state = STATE_SEEKING_FOOD # 初始狀態為尋找食物

    def calculate_target_direction(self):
        self.Total_x = 0 # 用於累加食物引力
        self.Total_y = 0
        ant_center_x = self.rect.centerx
        ant_center_y = self.rect.centery

        if self.state == STATE_SEEKING_FOOD:
            if not food_list: # 檢查 food_list 是否為空
                self.ANT_directionx = random.uniform(-1, 1)
                self.ANT_directiony = random.uniform(-1, 1)
            else:
                for food_coords in food_list:
                    distance = math.hypot(food_coords[0] - ant_center_x, food_coords[1] - ant_center_y) # 使用 math.hypot
                    if distance < 1:
                        # 避免除以零，並在極近時給予微小擾動或直接跳過
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

        norm_direction = math.hypot(self.ANT_directionx, self.ANT_directiony)

        if norm_direction > 0.01: # 僅在有明確方向時計算目標速度
            target_vx = (self.ANT_directionx / norm_direction) * ANT_SPEED
            target_vy = (self.ANT_directiony / norm_direction) * ANT_SPEED
        else: # 如果方向不明確 (或極小)，則繼承當前速度或隨機
             target_vx = self.velocity_x * 0.9 # 稍微減速或保持
             target_vy = self.velocity_y * 0.9
             if math.hypot(target_vx, target_vy) < 0.1: # 如果太慢，給點隨機力
                angle = random.uniform(0, 2 * math.pi)
                target_vx += math.cos(angle) * 0.5
                target_vy += math.sin(angle) * 0.5

        self.velocity_x = self.velocity_x * (1 - self.smoothing_factor) + target_vx * self.smoothing_factor
        self.velocity_y = self.velocity_y * (1 - self.smoothing_factor) + target_vy * self.smoothing_factor

        current_actual_speed = math.hypot(self.velocity_x, self.velocity_y)
        if current_actual_speed > ANT_SPEED:
            self.velocity_x = (self.velocity_x / current_actual_speed) * ANT_SPEED
            self.velocity_y = (self.velocity_y / current_actual_speed) * ANT_SPEED

    def update(self):
        self.update_velocity()
        
        self.rect.x += self.velocity_x
        self.rect.y += self.velocity_y

        # 更新螞蟻顏色根據狀態
        if self.state == STATE_SEEKING_FOOD:
            if self.image is not self.image_original_white:
                self.image = self.image_original_white.copy()
        elif self.state == STATE_RETURNING_HOME:
            if self.image is not self.image_original_yellow:
                self.image = self.image_original_yellow.copy()

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


# 食物類 (Food Class - 您的程式碼，保持不變)
class Food(pg.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image = pg.Surface((10, 10))
        self.image.fill((255, 0, 0)) # 紅色
        self.rect = self.image.get_rect()
        margin = 100
        self.rect.center = (random.randint(margin, WIDTH - margin), random.randint(margin, HEIGHT - margin))
        
        # --- 修改：確保 food_list 是全域的，並加入 ---
        global food_list
        food_list.append(list(self.rect.center))

# --- 新增：主遊戲函式 ---
def run_ant_simulation():
    """這個函式包含了所有 Pygame 的啟動和執行邏輯。"""
    pg.init() # 將初始化移到這裡
    
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
    for _ in range(5): # 您原本是 5 隻
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

        # 碰撞處理
        picked_foods_dict = pg.sprite.groupcollide(foods, ants, True, False)
        for food_collided, colliding_ants_list in picked_foods_dict.items():
            center_coords_to_remove = list(food_collided.rect.center)
            if center_coords_to_remove in food_list:
                food_list.remove(center_coords_to_remove)
            
            for ant_involved in colliding_ants_list:
                if isinstance(ant_involved, Ant):
                    ant_involved.state = STATE_RETURNING_HOME

            # 產生新食物 (您原本是 1 個)
            new_food = Food()
            all_sprites.add(new_food)
            foods.add(new_food)

        # 更新所有精靈
        all_sprites.update()

        # 繪製畫面
        screen.fill((0, 0, 0)) # 黑色背景
        
        # 繪製家 (藍色圓圈)
        pg.draw.circle(screen, (0, 0, 255), HOME_POSITION, HOME_RADIUS, 1)

        # 繪製所有精靈
        all_sprites.draw(screen)
        
        # 更新顯示
        pg.display.flip()

    pg.quit() # 結束 Pygame

# --- 關鍵部分：確保只在直接執行時才跑遊戲 ---
if __name__ == "__main__":
    run_ant_simulation()