<template>
  <div class="register-page">
    <!-- Left Panel - Characters -->
    <div class="left-panel hidden lg:flex">
      <!-- Decorative blurs -->
      <div class="blur-orb blur-orb-1"></div>
      <div class="blur-orb blur-orb-2"></div>

      <!-- Logo -->
      <div class="left-logo">
        <template v-if="appStore.publicSettingsLoaded">
          <div class="left-logo-icon">
            <img :src="logoUrl || '/logo.png'" alt="Logo" class="h-full w-full object-contain" />
          </div>
          <span class="left-logo-text">{{ appStore.siteName || 'Sub2API' }}</span>
        </template>
      </div>

      <!-- Characters Scene -->
      <div class="characters-wrapper">
        <div class="characters-scene" ref="sceneRef">
          <!-- Teal/Primary character (was purple) -->
          <div class="character char-primary" ref="charPrimary">
            <div class="eyes" ref="primaryEyes" :style="{ left: '45px', top: '40px', gap: '28px' }">
              <div class="eyeball" ref="primaryEyeL" :style="{ width: '18px', height: primaryBlinking ? '2px' : '18px' }">
                <div class="pupil" ref="primaryPupilL" style="width:7px;height:7px;"></div>
              </div>
              <div class="eyeball" ref="primaryEyeR" :style="{ width: '18px', height: primaryBlinking ? '2px' : '18px' }">
                <div class="pupil" ref="primaryPupilR" style="width:7px;height:7px;"></div>
              </div>
            </div>
          </div>
          <!-- Dark character (was black) -->
          <div class="character char-dark" ref="charDark">
            <div class="eyes" ref="darkEyes" :style="{ left: '26px', top: '32px', gap: '20px' }">
              <div class="eyeball" ref="darkEyeL" :style="{ width: '16px', height: darkBlinking ? '2px' : '16px' }">
                <div class="pupil" ref="darkPupilL" style="width:6px;height:6px;"></div>
              </div>
              <div class="eyeball" ref="darkEyeR" :style="{ width: '16px', height: darkBlinking ? '2px' : '16px' }">
                <div class="pupil" ref="darkPupilR" style="width:6px;height:6px;"></div>
              </div>
            </div>
          </div>
          <!-- Orange character -->
          <div class="character char-orange" ref="charOrange">
            <div class="eyes" ref="orangeEyes" :style="{ left: '82px', top: '90px', gap: '28px' }">
              <div class="bare-pupil" ref="orangePupilL"></div>
              <div class="bare-pupil" ref="orangePupilR"></div>
            </div>
            <div class="orange-mouth" ref="orangeMouth" :class="{ visible: showOrangeMouth }" :style="{ left: '90px', top: '120px' }"></div>
          </div>
          <!-- Yellow character -->
          <div class="character char-yellow" ref="charYellow">
            <div class="eyes" ref="yellowEyes" :style="{ left: '52px', top: '40px', gap: '20px' }">
              <div class="bare-pupil" ref="yellowPupilL"></div>
              <div class="bare-pupil" ref="yellowPupilR"></div>
            </div>
            <div class="yellow-mouth" ref="yellowMouth" :style="{ left: '40px', top: '88px' }"></div>
          </div>
        </div>
      </div>

      <!-- Footer -->
      <div class="left-footer">
        <span>&copy; {{ currentYear }} {{ appStore.siteName || 'Sub2API' }}</span>
      </div>
    </div>

    <!-- Right Panel - Form -->
    <div class="right-panel">
      <div class="form-container">
        <!-- Mobile logo (shown on small screens only) -->
        <div class="mb-6 text-center lg:hidden">
          <template v-if="appStore.publicSettingsLoaded">
            <div class="mb-3 inline-flex h-14 w-14 items-center justify-center overflow-hidden rounded-2xl shadow-lg shadow-primary-500/30">
              <img :src="logoUrl || '/logo.png'" alt="Logo" class="h-full w-full object-contain" />
            </div>
            <h1 class="text-gradient mb-1 text-2xl font-bold">{{ appStore.siteName || 'Sub2API' }}</h1>
          </template>
        </div>

        <div class="space-y-6">
          <!-- Title -->
          <div class="text-center">
            <h2 class="form-title">
              {{ t('auth.createAccount') }}
            </h2>
            <p class="form-subtitle">
              {{ t('auth.signUpToStart', { siteName }) }}
            </p>
          </div>

          <!-- LinuxDo Connect OAuth -->
          <LinuxDoOAuthSection v-if="linuxdoOAuthEnabled" :disabled="isLoading" />

          <!-- Registration Disabled -->
          <div
            v-if="!registrationEnabled && settingsLoaded"
            class="rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-800/50 dark:bg-amber-900/20"
          >
            <div class="flex items-start gap-3">
              <div class="flex-shrink-0">
                <Icon name="exclamationCircle" size="md" class="text-amber-500" />
              </div>
              <p class="text-sm text-amber-700 dark:text-amber-400">
                {{ t('auth.registrationDisabled') }}
              </p>
            </div>
          </div>

          <!-- Registration Form -->
          <form v-else @submit.prevent="handleRegister" class="space-y-5">
            <!-- Email -->
            <div class="form-group">
              <label for="email" class="form-label">{{ t('auth.emailLabel') }}</label>
              <div class="input-wrapper">
                <input
                  id="email"
                  ref="emailInputRef"
                  v-model="formData.email"
                  type="email"
                  required
                  autofocus
                  autocomplete="email"
                  :disabled="isLoading"
                  class="form-input"
                  :class="{ 'error': errors.email }"
                  :placeholder="t('auth.emailPlaceholder')"
                  @focus="onEmailFocus"
                  @blur="onEmailBlur"
                  @input="onEmailInput"
                />
              </div>
              <p v-if="errors.email" class="input-error-text">{{ errors.email }}</p>
            </div>

            <!-- Password -->
            <div class="form-group">
              <label for="password" class="form-label">{{ t('auth.passwordLabel') }}</label>
              <div class="input-wrapper">
                <input
                  id="password"
                  ref="passwordInputRef"
                  v-model="formData.password"
                  :type="showPassword ? 'text' : 'password'"
                  required
                  autocomplete="new-password"
                  :disabled="isLoading"
                  class="form-input pr-10"
                  :class="{ 'error': errors.password }"
                  :placeholder="t('auth.createPasswordPlaceholder')"
                  @focus="onPasswordFocus"
                  @blur="onPasswordBlur"
                  @input="onPasswordInput"
                />
                <button
                  type="button"
                  @click="togglePassword"
                  class="toggle-password"
                >
                  <Icon v-if="showPassword" name="eyeOff" size="md" />
                  <Icon v-else name="eye" size="md" />
                </button>
              </div>
              <p v-if="errors.password" class="input-error-text">{{ errors.password }}</p>
              <p v-else class="input-hint">{{ t('auth.passwordHint') }}</p>
            </div>

            <!-- Invitation Code -->
            <div v-if="invitationCodeEnabled" class="form-group">
              <label for="invitation_code" class="form-label">{{ t('auth.invitationCodeLabel') }}</label>
              <div class="input-wrapper">
                <input
                  id="invitation_code"
                  v-model="formData.invitation_code"
                  type="text"
                  :disabled="isLoading"
                  class="form-input pr-10"
                  :class="{
                    'valid': invitationValidation.valid,
                    'error': invitationValidation.invalid || errors.invitation_code
                  }"
                  :placeholder="t('auth.invitationCodePlaceholder')"
                  @input="handleInvitationCodeInput"
                />
                <div v-if="invitationValidating" class="input-suffix">
                  <svg class="h-4 w-4 animate-spin text-gray-400" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                </div>
                <div v-else-if="invitationValidation.valid" class="input-suffix">
                  <Icon name="checkCircle" size="md" class="text-green-500" />
                </div>
                <div v-else-if="invitationValidation.invalid || errors.invitation_code" class="input-suffix">
                  <Icon name="exclamationCircle" size="md" class="text-red-500" />
                </div>
              </div>
              <transition name="fade">
                <div v-if="invitationValidation.valid" class="mt-2 flex items-center gap-2 rounded-lg bg-green-50 px-3 py-2 dark:bg-green-900/20">
                  <Icon name="checkCircle" size="sm" class="text-green-600 dark:text-green-400" />
                  <span class="text-sm text-green-700 dark:text-green-400">{{ t('auth.invitationCodeValid') }}</span>
                </div>
                <p v-else-if="invitationValidation.invalid" class="input-error-text">{{ invitationValidation.message }}</p>
                <p v-else-if="errors.invitation_code" class="input-error-text">{{ errors.invitation_code }}</p>
              </transition>
            </div>

            <!-- Promo Code -->
            <div v-if="promoCodeEnabled" class="form-group">
              <label for="promo_code" class="form-label">
                {{ t('auth.promoCodeLabel') }}
                <span class="ml-1 text-xs font-normal text-gray-400 dark:text-dark-500">({{ t('common.optional') }})</span>
              </label>
              <div class="input-wrapper">
                <input
                  id="promo_code"
                  v-model="formData.promo_code"
                  type="text"
                  :disabled="isLoading"
                  class="form-input pr-10"
                  :class="{
                    'valid': promoValidation.valid,
                    'error': promoValidation.invalid
                  }"
                  :placeholder="t('auth.promoCodePlaceholder')"
                  @input="handlePromoCodeInput"
                />
                <div v-if="promoValidating" class="input-suffix">
                  <svg class="h-4 w-4 animate-spin text-gray-400" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                </div>
                <div v-else-if="promoValidation.valid" class="input-suffix">
                  <Icon name="checkCircle" size="md" class="text-green-500" />
                </div>
                <div v-else-if="promoValidation.invalid" class="input-suffix">
                  <Icon name="exclamationCircle" size="md" class="text-red-500" />
                </div>
              </div>
              <transition name="fade">
                <div v-if="promoValidation.valid" class="mt-2 flex items-center gap-2 rounded-lg bg-green-50 px-3 py-2 dark:bg-green-900/20">
                  <Icon name="gift" size="sm" class="text-green-600 dark:text-green-400" />
                  <span class="text-sm text-green-700 dark:text-green-400">{{ t('auth.promoCodeValid', { amount: promoValidation.bonusAmount?.toFixed(2) }) }}</span>
                </div>
                <p v-else-if="promoValidation.invalid" class="input-error-text">{{ promoValidation.message }}</p>
              </transition>
            </div>

            <!-- Referral Code -->
            <div v-if="referralEnabled" class="form-group">
              <label for="referral_code" class="form-label">{{ t('auth.referralCodeLabel') }}</label>
              <div class="input-wrapper">
                <input
                  id="referral_code"
                  v-model="formData.referral_code"
                  type="text"
                  :disabled="isLoading"
                  class="form-input"
                  :placeholder="t('auth.referralCodePlaceholder')"
                />
              </div>
            </div>

            <!-- Turnstile -->
            <div v-if="turnstileEnabled && turnstileSiteKey">
              <TurnstileWidget
                ref="turnstileRef"
                :site-key="turnstileSiteKey"
                @verify="onTurnstileVerify"
                @expire="onTurnstileExpire"
                @error="onTurnstileError"
              />
              <p v-if="errors.turnstile" class="input-error-text mt-2 text-center">{{ errors.turnstile }}</p>
            </div>

            <!-- Error Message -->
            <transition name="fade">
              <div
                v-if="errorMessage"
                class="error-banner"
              >
                <Icon name="exclamationCircle" size="md" class="flex-shrink-0 text-red-500" />
                <p class="text-sm text-red-700 dark:text-red-400">{{ errorMessage }}</p>
              </div>
            </transition>

            <!-- Submit -->
            <button
              type="submit"
              :disabled="isLoading || (turnstileEnabled && !turnstileToken)"
              class="submit-btn"
            >
              <span class="btn-text">
                <svg v-if="isLoading" class="-ml-1 mr-2 h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <Icon v-else name="userPlus" size="md" class="mr-2" />
                {{ isLoading ? t('auth.processing') : emailVerifyEnabled ? t('auth.continue') : t('auth.createAccount') }}
              </span>
              <div class="btn-hover-content">
                <span>{{ isLoading ? t('auth.processing') : emailVerifyEnabled ? t('auth.continue') : t('auth.createAccount') }}</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
              </div>
            </button>
          </form>

          <!-- Footer link -->
          <div class="mt-6 text-center text-sm">
            <p class="text-gray-500 dark:text-dark-400">
              {{ t('auth.alreadyHaveAccount') }}
              <router-link
                to="/login"
                class="font-medium text-primary-600 transition-colors hover:text-primary-500 dark:text-primary-400 dark:hover:text-primary-300"
              >
                {{ t('auth.signIn') }}
              </router-link>
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import LinuxDoOAuthSection from '@/components/auth/LinuxDoOAuthSection.vue'
import Icon from '@/components/icons/Icon.vue'
import TurnstileWidget from '@/components/TurnstileWidget.vue'
import { useAuthStore, useAppStore } from '@/stores'
import { getPublicSettings, validatePromoCode, validateInvitationCode } from '@/api/auth'
import { buildAuthErrorMessage } from '@/utils/authError'
import { sanitizeUrl } from '@/utils/url'
import {
  isRegistrationEmailSuffixAllowed,
  normalizeRegistrationEmailSuffixWhitelist
} from '@/utils/registrationEmailPolicy'

const { t, locale } = useI18n()

// ==================== Router & Stores ====================

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const appStore = useAppStore()

const logoUrl = computed(() => sanitizeUrl(appStore.siteLogo || '', { allowRelative: true, allowDataUrl: true }))
const currentYear = computed(() => new Date().getFullYear())

// ==================== Form State ====================

const isLoading = ref(false)
const settingsLoaded = ref(false)
const errorMessage = ref('')
const showPassword = ref(false)

const registrationEnabled = ref(true)
const emailVerifyEnabled = ref(false)
const promoCodeEnabled = ref(true)
const invitationCodeEnabled = ref(false)
const turnstileEnabled = ref(false)
const turnstileSiteKey = ref('')
const siteName = ref('Sub2API')
const linuxdoOAuthEnabled = ref(false)
const registrationEmailSuffixWhitelist = ref<string[]>([])
const referralEnabled = ref(false)

const turnstileRef = ref<InstanceType<typeof TurnstileWidget> | null>(null)
const turnstileToken = ref('')

const promoValidating = ref(false)
const promoValidation = reactive({
  valid: false,
  invalid: false,
  bonusAmount: null as number | null,
  message: ''
})
let promoValidateTimeout: ReturnType<typeof setTimeout> | null = null

const invitationValidating = ref(false)
const invitationValidation = reactive({
  valid: false,
  invalid: false,
  message: ''
})
let invitationValidateTimeout: ReturnType<typeof setTimeout> | null = null

const formData = reactive({
  email: '',
  password: '',
  promo_code: '',
  invitation_code: '',
  referral_code: ''
})

const errors = reactive({
  email: '',
  password: '',
  turnstile: '',
  invitation_code: ''
})

// ==================== Character Animation Refs ====================

const sceneRef = ref<HTMLElement | null>(null)
const charPrimary = ref<HTMLElement | null>(null)
const charDark = ref<HTMLElement | null>(null)
const charOrange = ref<HTMLElement | null>(null)
const charYellow = ref<HTMLElement | null>(null)

const primaryEyes = ref<HTMLElement | null>(null)
const primaryEyeL = ref<HTMLElement | null>(null)
const primaryEyeR = ref<HTMLElement | null>(null)
const primaryPupilL = ref<HTMLElement | null>(null)
const primaryPupilR = ref<HTMLElement | null>(null)

const darkEyes = ref<HTMLElement | null>(null)
const darkEyeL = ref<HTMLElement | null>(null)
const darkEyeR = ref<HTMLElement | null>(null)
const darkPupilL = ref<HTMLElement | null>(null)
const darkPupilR = ref<HTMLElement | null>(null)

const orangeEyes = ref<HTMLElement | null>(null)
const orangePupilL = ref<HTMLElement | null>(null)
const orangePupilR = ref<HTMLElement | null>(null)
const orangeMouth = ref<HTMLElement | null>(null)

const yellowEyes = ref<HTMLElement | null>(null)
const yellowPupilL = ref<HTMLElement | null>(null)
const yellowPupilR = ref<HTMLElement | null>(null)
const yellowMouth = ref<HTMLElement | null>(null)

const emailInputRef = ref<HTMLInputElement | null>(null)
const passwordInputRef = ref<HTMLInputElement | null>(null)

// Character state
let mouseX = 0
let mouseY = 0
const primaryBlinking = ref(false)
const darkBlinking = ref(false)
let isTyping = false
let isLookingAtEachOther = false
let isPasswordFocused = false
let isRegisterError = false
let isPrimaryPeeking = false
const showOrangeMouth = ref(false)
let typingTimer: ReturnType<typeof setTimeout> | null = null
let blinkTimerPrimary: ReturnType<typeof setTimeout> | null = null
let blinkTimerDark: ReturnType<typeof setTimeout> | null = null
let peekTimer: ReturnType<typeof setTimeout> | null = null
let errorRecoverTimer: ReturnType<typeof setTimeout> | null = null

// ==================== Character Animation Logic ====================

function calcPosition(el: HTMLElement | null) {
  if (!el) return { faceX: 0, faceY: 0, bodySkew: 0 }
  const rect = el.getBoundingClientRect()
  const cx = rect.left + rect.width / 2
  const cy = rect.top + rect.height / 3
  const dx = mouseX - cx
  const dy = mouseY - cy
  return {
    faceX: Math.max(-15, Math.min(15, dx / 20)),
    faceY: Math.max(-10, Math.min(10, dy / 30)),
    bodySkew: Math.max(-6, Math.min(6, -dx / 120))
  }
}

function calcPupilOffset(el: HTMLElement | null, maxDist: number) {
  if (!el) return { x: 0, y: 0 }
  const rect = el.getBoundingClientRect()
  const cx = rect.left + rect.width / 2
  const cy = rect.top + rect.height / 2
  const dx = mouseX - cx
  const dy = mouseY - cy
  const dist = Math.min(Math.sqrt(dx * dx + dy * dy), maxDist)
  const angle = Math.atan2(dy, dx)
  return { x: Math.cos(angle) * dist, y: Math.sin(angle) * dist }
}

function updateCharacters() {
  if (!charPrimary.value) return

  const pPos = calcPosition(charPrimary.value)
  const dPos = calcPosition(charDark.value)
  const oPos = calcPosition(charOrange.value)
  const yPos = calcPosition(charYellow.value)

  const pwdLen = formData.password.length
  const isShowingPwd = pwdLen > 0 && showPassword.value
  const isLookingAway = isPasswordFocused && !showPassword.value

  // ---- Primary body ----
  if (charPrimary.value) {
    if (isShowingPwd) {
      charPrimary.value.style.transform = 'skewX(0deg)'
      charPrimary.value.style.height = '370px'
    } else if (isLookingAway) {
      charPrimary.value.style.transform = 'skewX(-14deg) translateX(-20px)'
      charPrimary.value.style.height = '410px'
    } else if (isTyping) {
      charPrimary.value.style.transform = `skewX(${(pPos.bodySkew || 0) - 12}deg) translateX(40px)`
      charPrimary.value.style.height = '410px'
    } else {
      charPrimary.value.style.transform = `skewX(${pPos.bodySkew}deg)`
      charPrimary.value.style.height = '370px'
    }
  }

  // Primary eyes
  if (primaryEyes.value && primaryPupilL.value && primaryPupilR.value) {
    if (isRegisterError) {
      primaryEyes.value.style.left = '30px'
      primaryEyes.value.style.top = '55px'
      primaryPupilL.value.style.transform = 'translate(-3px, 4px)'
      primaryPupilR.value.style.transform = 'translate(-3px, 4px)'
    } else if (isLookingAway) {
      primaryEyes.value.style.left = '20px'
      primaryEyes.value.style.top = '25px'
      primaryPupilL.value.style.transform = 'translate(-5px, -5px)'
      primaryPupilR.value.style.transform = 'translate(-5px, -5px)'
    } else if (isShowingPwd) {
      primaryEyes.value.style.left = '20px'
      primaryEyes.value.style.top = '35px'
      const px = isPrimaryPeeking ? 4 : -4
      const py = isPrimaryPeeking ? 5 : -4
      primaryPupilL.value.style.transform = `translate(${px}px, ${py}px)`
      primaryPupilR.value.style.transform = `translate(${px}px, ${py}px)`
    } else if (isLookingAtEachOther) {
      primaryEyes.value.style.left = '55px'
      primaryEyes.value.style.top = '65px'
      primaryPupilL.value.style.transform = 'translate(3px, 4px)'
      primaryPupilR.value.style.transform = 'translate(3px, 4px)'
    } else {
      primaryEyes.value.style.left = (45 + pPos.faceX) + 'px'
      primaryEyes.value.style.top = (40 + pPos.faceY) + 'px'
      const po = calcPupilOffset(primaryEyeL.value, 5)
      primaryPupilL.value.style.transform = `translate(${po.x}px, ${po.y}px)`
      primaryPupilR.value.style.transform = `translate(${po.x}px, ${po.y}px)`
    }
  }

  // ---- Dark body ----
  if (charDark.value) {
    if (isShowingPwd) {
      charDark.value.style.transform = 'skewX(0deg)'
    } else if (isLookingAway) {
      charDark.value.style.transform = 'skewX(12deg) translateX(-10px)'
    } else if (isLookingAtEachOther) {
      charDark.value.style.transform = `skewX(${(dPos.bodySkew || 0) * 1.5 + 10}deg) translateX(20px)`
    } else if (isTyping) {
      charDark.value.style.transform = `skewX(${(dPos.bodySkew || 0) * 1.5}deg)`
    } else {
      charDark.value.style.transform = `skewX(${dPos.bodySkew}deg)`
    }
  }

  // Dark eyes
  if (darkEyes.value && darkPupilL.value && darkPupilR.value) {
    if (isRegisterError) {
      darkEyes.value.style.left = '15px'
      darkEyes.value.style.top = '40px'
      darkPupilL.value.style.transform = 'translate(-3px, 4px)'
      darkPupilR.value.style.transform = 'translate(-3px, 4px)'
    } else if (isLookingAway) {
      darkEyes.value.style.left = '10px'
      darkEyes.value.style.top = '20px'
      darkPupilL.value.style.transform = 'translate(-4px, -5px)'
      darkPupilR.value.style.transform = 'translate(-4px, -5px)'
    } else if (isShowingPwd) {
      darkEyes.value.style.left = '10px'
      darkEyes.value.style.top = '28px'
      darkPupilL.value.style.transform = 'translate(-4px, -4px)'
      darkPupilR.value.style.transform = 'translate(-4px, -4px)'
    } else if (isLookingAtEachOther) {
      darkEyes.value.style.left = '32px'
      darkEyes.value.style.top = '12px'
      darkPupilL.value.style.transform = 'translate(0px, -4px)'
      darkPupilR.value.style.transform = 'translate(0px, -4px)'
    } else {
      darkEyes.value.style.left = (26 + dPos.faceX) + 'px'
      darkEyes.value.style.top = (32 + dPos.faceY) + 'px'
      const bo = calcPupilOffset(darkEyeL.value, 4)
      darkPupilL.value.style.transform = `translate(${bo.x}px, ${bo.y}px)`
      darkPupilR.value.style.transform = `translate(${bo.x}px, ${bo.y}px)`
    }
  }

  // ---- Orange body ----
  if (charOrange.value) {
    if (isShowingPwd) {
      charOrange.value.style.transform = 'skewX(0deg)'
    } else {
      charOrange.value.style.transform = `skewX(${oPos.bodySkew}deg)`
    }
  }

  if (orangeEyes.value && orangePupilL.value && orangePupilR.value) {
    if (isRegisterError) {
      orangeEyes.value.style.left = '60px'
      orangeEyes.value.style.top = '95px'
      orangePupilL.value.style.transform = 'translate(-3px, 4px)'
      orangePupilR.value.style.transform = 'translate(-3px, 4px)'
      if (orangeMouth.value) {
        orangeMouth.value.style.left = (80 + oPos.faceX) + 'px'
        orangeMouth.value.style.top = '130px'
      }
    } else if (isLookingAway) {
      orangeEyes.value.style.left = '50px'
      orangeEyes.value.style.top = '75px'
      orangePupilL.value.style.transform = 'translate(-5px, -5px)'
      orangePupilR.value.style.transform = 'translate(-5px, -5px)'
    } else if (isShowingPwd) {
      orangeEyes.value.style.left = '50px'
      orangeEyes.value.style.top = '85px'
      orangePupilL.value.style.transform = 'translate(-5px, -4px)'
      orangePupilR.value.style.transform = 'translate(-5px, -4px)'
    } else {
      orangeEyes.value.style.left = (82 + oPos.faceX) + 'px'
      orangeEyes.value.style.top = (90 + oPos.faceY) + 'px'
      const oo = calcPupilOffset(orangePupilL.value, 5)
      orangePupilL.value.style.transform = `translate(${oo.x}px, ${oo.y}px)`
      orangePupilR.value.style.transform = `translate(${oo.x}px, ${oo.y}px)`
    }
  }

  // ---- Yellow body ----
  if (charYellow.value) {
    if (isShowingPwd) {
      charYellow.value.style.transform = 'skewX(0deg)'
    } else {
      charYellow.value.style.transform = `skewX(${yPos.bodySkew}deg)`
    }
  }

  if (yellowEyes.value && yellowPupilL.value && yellowPupilR.value && yellowMouth.value) {
    if (isRegisterError) {
      yellowEyes.value.style.left = '35px'
      yellowEyes.value.style.top = '45px'
      yellowPupilL.value.style.transform = 'translate(-3px, 4px)'
      yellowPupilR.value.style.transform = 'translate(-3px, 4px)'
      yellowMouth.value.style.left = '30px'
      yellowMouth.value.style.top = '92px'
      yellowMouth.value.style.transform = 'rotate(-8deg)'
    } else if (isLookingAway) {
      yellowEyes.value.style.left = '20px'
      yellowEyes.value.style.top = '30px'
      yellowPupilL.value.style.transform = 'translate(-5px, -5px)'
      yellowPupilR.value.style.transform = 'translate(-5px, -5px)'
      yellowMouth.value.style.left = '15px'
      yellowMouth.value.style.top = '78px'
      yellowMouth.value.style.transform = 'rotate(0deg)'
    } else if (isShowingPwd) {
      yellowEyes.value.style.left = '20px'
      yellowEyes.value.style.top = '35px'
      yellowPupilL.value.style.transform = 'translate(-5px, -4px)'
      yellowPupilR.value.style.transform = 'translate(-5px, -4px)'
      yellowMouth.value.style.left = '10px'
      yellowMouth.value.style.top = '88px'
      yellowMouth.value.style.transform = 'rotate(0deg)'
    } else {
      yellowEyes.value.style.left = (52 + yPos.faceX) + 'px'
      yellowEyes.value.style.top = (40 + yPos.faceY) + 'px'
      const yo = calcPupilOffset(yellowPupilL.value, 5)
      yellowPupilL.value.style.transform = `translate(${yo.x}px, ${yo.y}px)`
      yellowPupilR.value.style.transform = `translate(${yo.x}px, ${yo.y}px)`
      yellowMouth.value.style.left = (40 + yPos.faceX) + 'px'
      yellowMouth.value.style.top = (88 + yPos.faceY) + 'px'
      yellowMouth.value.style.transform = 'rotate(0deg)'
    }
  }
}

// Blinking
function scheduleBlinkPrimary() {
  blinkTimerPrimary = setTimeout(() => {
    primaryBlinking.value = true
    updateCharacters()
    setTimeout(() => {
      primaryBlinking.value = false
      updateCharacters()
      scheduleBlinkPrimary()
    }, 150)
  }, Math.random() * 4000 + 3000)
}

function scheduleBlinkDark() {
  blinkTimerDark = setTimeout(() => {
    darkBlinking.value = true
    updateCharacters()
    setTimeout(() => {
      darkBlinking.value = false
      updateCharacters()
      scheduleBlinkDark()
    }, 150)
  }, Math.random() * 4000 + 3000)
}

function schedulePeek() {
  if (formData.password.length > 0 && showPassword.value) {
    peekTimer = setTimeout(() => {
      if (formData.password.length > 0 && showPassword.value) {
        isPrimaryPeeking = true
        updateCharacters()
        setTimeout(() => {
          isPrimaryPeeking = false
          updateCharacters()
          schedulePeek()
        }, 800)
      }
    }, Math.random() * 3000 + 2000)
  }
}

function setTypingState(typing: boolean) {
  isTyping = typing
  if (typing) {
    isLookingAtEachOther = true
    if (typingTimer) clearTimeout(typingTimer)
    typingTimer = setTimeout(() => {
      isLookingAtEachOther = false
      updateCharacters()
    }, 800)
  } else {
    isLookingAtEachOther = false
  }
  updateCharacters()
}

function triggerErrorAnimation() {
  if (errorRecoverTimer) {
    clearTimeout(errorRecoverTimer)
    errorRecoverTimer = null
  }

  // Remove shake classes first
  const shakeEls = [primaryEyes.value, darkEyes.value, orangeEyes.value, yellowEyes.value, yellowMouth.value, orangeMouth.value]
  shakeEls.forEach(el => el?.classList.remove('shake-head'))

  isRegisterError = true
  isPasswordFocused = false
  updateCharacters()

  showOrangeMouth.value = true

  setTimeout(() => {
    shakeEls.forEach(el => el?.classList.add('shake-head'))
  }, 350)

  errorRecoverTimer = setTimeout(() => {
    isRegisterError = false
    errorRecoverTimer = null
    showOrangeMouth.value = false
    shakeEls.forEach(el => el?.classList.remove('shake-head'))
    updateCharacters()
  }, 2500)
}

// Form input handlers for character reactions
function onEmailFocus() { setTypingState(true) }
function onEmailBlur() { setTypingState(false) }
function onEmailInput() { updateCharacters() }
function onPasswordFocus() { isPasswordFocused = true; updateCharacters() }
function onPasswordBlur() { isPasswordFocused = false; updateCharacters() }
function onPasswordInput() { updateCharacters() }

function togglePassword() {
  showPassword.value = !showPassword.value
  updateCharacters()
  if (showPassword.value) schedulePeek()
}

function onMouseMove(e: MouseEvent) {
  mouseX = e.clientX
  mouseY = e.clientY
  if (!isTyping && !isRegisterError) updateCharacters()
}

// ==================== Lifecycle ====================

onMounted(async () => {
  document.addEventListener('mousemove', onMouseMove)
  scheduleBlinkPrimary()
  scheduleBlinkDark()

  try {
    const settings = await getPublicSettings()
    registrationEnabled.value = settings.registration_enabled
    emailVerifyEnabled.value = settings.email_verify_enabled
    promoCodeEnabled.value = settings.promo_code_enabled
    invitationCodeEnabled.value = settings.invitation_code_enabled
    turnstileEnabled.value = settings.turnstile_enabled
    turnstileSiteKey.value = settings.turnstile_site_key || ''
    siteName.value = settings.site_name || 'Sub2API'
    linuxdoOAuthEnabled.value = settings.linuxdo_oauth_enabled
    registrationEmailSuffixWhitelist.value = normalizeRegistrationEmailSuffixWhitelist(
      settings.registration_email_suffix_whitelist || []
    )
    referralEnabled.value = settings.referral_enabled || false

    if (referralEnabled.value) {
      const refParam = route.query.ref as string
      if (refParam) formData.referral_code = refParam
    }

    if (promoCodeEnabled.value) {
      const promoParam = route.query.promo as string
      if (promoParam) {
        formData.promo_code = promoParam
        await validatePromoCodeDebounced(promoParam)
      }
    }
  } catch (error) {
    console.error('Failed to load public settings:', error)
  } finally {
    settingsLoaded.value = true
  }
})

onUnmounted(() => {
  document.removeEventListener('mousemove', onMouseMove)
  if (promoValidateTimeout) clearTimeout(promoValidateTimeout)
  if (invitationValidateTimeout) clearTimeout(invitationValidateTimeout)
  if (blinkTimerPrimary) clearTimeout(blinkTimerPrimary)
  if (blinkTimerDark) clearTimeout(blinkTimerDark)
  if (peekTimer) clearTimeout(peekTimer)
  if (typingTimer) clearTimeout(typingTimer)
  if (errorRecoverTimer) clearTimeout(errorRecoverTimer)
})

// ==================== Promo Code Validation ====================

function handlePromoCodeInput(): void {
  const code = formData.promo_code.trim()
  promoValidation.valid = false
  promoValidation.invalid = false
  promoValidation.bonusAmount = null
  promoValidation.message = ''

  if (!code) { promoValidating.value = false; return }

  if (promoValidateTimeout) clearTimeout(promoValidateTimeout)
  promoValidateTimeout = setTimeout(() => { validatePromoCodeDebounced(code) }, 500)
}

async function validatePromoCodeDebounced(code: string): Promise<void> {
  if (!code.trim()) return
  promoValidating.value = true

  try {
    const result = await validatePromoCode(code)
    if (result.valid) {
      promoValidation.valid = true
      promoValidation.invalid = false
      promoValidation.bonusAmount = result.bonus_amount || 0
      promoValidation.message = ''
    } else {
      promoValidation.valid = false
      promoValidation.invalid = true
      promoValidation.bonusAmount = null
      promoValidation.message = getPromoErrorMessage(result.error_code)
    }
  } catch {
    promoValidation.valid = false
    promoValidation.invalid = true
    promoValidation.message = t('auth.promoCodeInvalid')
  } finally {
    promoValidating.value = false
  }
}

function getPromoErrorMessage(errorCode?: string): string {
  switch (errorCode) {
    case 'PROMO_CODE_NOT_FOUND': return t('auth.promoCodeNotFound')
    case 'PROMO_CODE_EXPIRED': return t('auth.promoCodeExpired')
    case 'PROMO_CODE_DISABLED': return t('auth.promoCodeDisabled')
    case 'PROMO_CODE_MAX_USED': return t('auth.promoCodeMaxUsed')
    case 'PROMO_CODE_ALREADY_USED': return t('auth.promoCodeAlreadyUsed')
    default: return t('auth.promoCodeInvalid')
  }
}

// ==================== Invitation Code Validation ====================

function handleInvitationCodeInput(): void {
  const code = formData.invitation_code.trim()
  invitationValidation.valid = false
  invitationValidation.invalid = false
  invitationValidation.message = ''
  errors.invitation_code = ''

  if (!code) return

  if (invitationValidateTimeout) clearTimeout(invitationValidateTimeout)
  invitationValidateTimeout = setTimeout(() => { validateInvitationCodeDebounced(code) }, 500)
}

async function validateInvitationCodeDebounced(code: string): Promise<void> {
  invitationValidating.value = true
  try {
    const result = await validateInvitationCode(code)
    if (result.valid) {
      invitationValidation.valid = true
      invitationValidation.invalid = false
      invitationValidation.message = ''
    } else {
      invitationValidation.valid = false
      invitationValidation.invalid = true
      invitationValidation.message = getInvitationErrorMessage(result.error_code)
    }
  } catch {
    invitationValidation.valid = false
    invitationValidation.invalid = true
    invitationValidation.message = t('auth.invitationCodeInvalid')
  } finally {
    invitationValidating.value = false
  }
}

function getInvitationErrorMessage(errorCode?: string): string {
  switch (errorCode) {
    case 'INVITATION_CODE_NOT_FOUND':
    case 'INVITATION_CODE_INVALID':
    case 'INVITATION_CODE_USED':
    case 'INVITATION_CODE_DISABLED':
    default:
      return t('auth.invitationCodeInvalid')
  }
}

// ==================== Turnstile Handlers ====================

function onTurnstileVerify(token: string): void {
  turnstileToken.value = token
  errors.turnstile = ''
}

function onTurnstileExpire(): void {
  turnstileToken.value = ''
  errors.turnstile = t('auth.turnstileExpired')
}

function onTurnstileError(): void {
  turnstileToken.value = ''
  errors.turnstile = t('auth.turnstileFailed')
}

// ==================== Validation ====================

function validateEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function buildEmailSuffixNotAllowedMessage(): string {
  const normalizedWhitelist = normalizeRegistrationEmailSuffixWhitelist(registrationEmailSuffixWhitelist.value)
  if (normalizedWhitelist.length === 0) return t('auth.emailSuffixNotAllowed')
  const separator = String(locale.value || '').toLowerCase().startsWith('zh') ? '\u3001' : ', '
  return t('auth.emailSuffixNotAllowedWithAllowed', { suffixes: normalizedWhitelist.join(separator) })
}

function validateForm(): boolean {
  errors.email = ''
  errors.password = ''
  errors.turnstile = ''
  errors.invitation_code = ''
  let isValid = true

  if (!formData.email.trim()) {
    errors.email = t('auth.emailRequired')
    isValid = false
  } else if (!validateEmail(formData.email)) {
    errors.email = t('auth.invalidEmail')
    isValid = false
  } else if (!isRegistrationEmailSuffixAllowed(formData.email, registrationEmailSuffixWhitelist.value)) {
    errors.email = buildEmailSuffixNotAllowedMessage()
    isValid = false
  }

  if (!formData.password) {
    errors.password = t('auth.passwordRequired')
    isValid = false
  } else if (formData.password.length < 6) {
    errors.password = t('auth.passwordMinLength')
    isValid = false
  }

  if (invitationCodeEnabled.value) {
    if (!formData.invitation_code.trim()) {
      errors.invitation_code = t('auth.invitationCodeRequired')
      isValid = false
    }
  }

  if (turnstileEnabled.value && !turnstileToken.value) {
    errors.turnstile = t('auth.completeVerification')
    isValid = false
  }

  return isValid
}

// ==================== Form Handlers ====================

async function handleRegister(): Promise<void> {
  errorMessage.value = ''

  if (!validateForm()) {
    triggerErrorAnimation()
    return
  }

  if (formData.promo_code.trim()) {
    if (promoValidating.value) { errorMessage.value = t('auth.promoCodeValidating'); return }
    if (promoValidation.invalid) { errorMessage.value = t('auth.promoCodeInvalidCannotRegister'); return }
  }

  if (invitationCodeEnabled.value) {
    if (invitationValidating.value) { errorMessage.value = t('auth.invitationCodeValidating'); return }
    if (invitationValidation.invalid) { errorMessage.value = t('auth.invitationCodeInvalidCannotRegister'); return }
    if (formData.invitation_code.trim() && !invitationValidation.valid) {
      errorMessage.value = t('auth.invitationCodeValidating')
      await validateInvitationCodeDebounced(formData.invitation_code.trim())
      if (!invitationValidation.valid) { errorMessage.value = t('auth.invitationCodeInvalidCannotRegister'); return }
    }
  }

  isLoading.value = true

  try {
    if (emailVerifyEnabled.value) {
      sessionStorage.setItem('register_data', JSON.stringify({
        email: formData.email,
        password: formData.password,
        turnstile_token: turnstileToken.value,
        promo_code: formData.promo_code || undefined,
        invitation_code: formData.invitation_code || undefined,
        referral_code: formData.referral_code || undefined
      }))
      await router.push('/email-verify')
      return
    }

    await authStore.register({
      email: formData.email,
      password: formData.password,
      turnstile_token: turnstileEnabled.value ? turnstileToken.value : undefined,
      promo_code: formData.promo_code || undefined,
      invitation_code: formData.invitation_code || undefined,
      referral_code: formData.referral_code || undefined
    })

    appStore.showSuccess(t('auth.accountCreatedSuccess', { siteName: siteName.value }))
    await router.push('/dashboard')
  } catch (error: unknown) {
    if (turnstileRef.value) {
      turnstileRef.value.reset()
      turnstileToken.value = ''
    }
    errorMessage.value = buildAuthErrorMessage(error, { fallback: t('auth.registrationFailed') })
    appStore.showError(errorMessage.value)
    triggerErrorAnimation()
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
/* ============ PAGE LAYOUT ============ */
.register-page {
  display: grid;
  grid-template-columns: 1fr;
  min-height: 100vh;
}

@media (min-width: 1024px) {
  .register-page {
    grid-template-columns: 1fr 1fr;
  }
}

/* ============ LEFT PANEL ============ */
.left-panel {
  position: relative;
  flex-direction: column;
  justify-content: space-between;
  background: linear-gradient(135deg, #d0f0eb 0%, #b2dfdb 50%, #a3d5ce 100%);
  padding: 40px 48px;
  overflow: hidden;
}

:root.dark .left-panel,
.dark .left-panel {
  background: linear-gradient(135deg, #134e4a 0%, #0f3d3a 50%, #0d3330 100%);
}

.blur-orb {
  position: absolute;
  border-radius: 50%;
  pointer-events: none;
}

.blur-orb-1 {
  top: 20%;
  right: 15%;
  width: 260px;
  height: 260px;
  background: rgba(20, 184, 166, 0.15);
  filter: blur(80px);
}

.blur-orb-2 {
  bottom: 15%;
  left: 10%;
  width: 350px;
  height: 350px;
  background: rgba(20, 184, 166, 0.1);
  filter: blur(100px);
}

.left-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  z-index: 10;
  position: relative;
}

.left-logo-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.15);
  backdrop-filter: blur(8px);
  padding: 2px;
}

.left-logo-text {
  font-size: 16px;
  font-weight: 600;
  color: #134e4a;
}

.dark .left-logo-text {
  color: #99f6e4;
}

.characters-wrapper {
  position: relative;
  z-index: 10;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  height: 420px;
}

.left-footer {
  z-index: 10;
  position: relative;
  font-size: 13px;
  color: rgba(19, 78, 74, 0.6);
}

.dark .left-footer {
  color: rgba(153, 246, 228, 0.4);
}

/* ============ RIGHT PANEL ============ */
.right-panel {
  display: flex;
  align-items: center;
  justify-content: center;
  background: #ffffff;
  padding: 40px 24px;
  overflow-y: auto;
}

.dark .right-panel {
  background: #111827;
}

.form-container {
  width: 100%;
  max-width: 420px;
}

.form-title {
  font-size: 26px;
  font-weight: 700;
  color: #1a1a2e;
  letter-spacing: -0.5px;
  margin-bottom: 6px;
}

.dark .form-title {
  color: #f3f4f6;
}

.form-subtitle {
  font-size: 14px;
  color: #9ca3af;
}

.text-gradient {
  @apply bg-gradient-to-r from-primary-600 to-primary-500 bg-clip-text text-transparent;
}

/* ============ FORM FIELDS ============ */
.form-group {
  margin-bottom: 0;
}

.form-label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: #374151;
  margin-bottom: 8px;
}

.dark .form-label {
  color: #d1d5db;
}

.input-wrapper {
  position: relative;
}

.form-input {
  width: 100%;
  height: 48px;
  border: none;
  border-bottom: 1.5px solid #e5e7eb;
  padding: 0 0;
  font-size: 15px;
  font-family: inherit;
  color: #1f2937;
  background: transparent;
  outline: none;
  transition: border-color 0.3s;
}

.dark .form-input {
  border-bottom-color: #374151;
  color: #f3f4f6;
}

.form-input:focus {
  border-bottom-color: #14b8a6;
}

.form-input::placeholder {
  color: #d1d5db;
}

.dark .form-input::placeholder {
  color: #4b5563;
}

.form-input.error {
  border-bottom-color: #ef4444;
}

.form-input.valid {
  border-bottom-color: #22c55e;
}

.input-suffix {
  position: absolute;
  right: 0;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  align-items: center;
  padding-right: 4px;
}

.toggle-password {
  position: absolute;
  right: 0;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  cursor: pointer;
  color: #9ca3af;
  padding: 6px;
  transition: color 0.2s;
}

.toggle-password:hover {
  color: #6b7280;
}

.dark .toggle-password {
  color: #6b7280;
}

.dark .toggle-password:hover {
  color: #9ca3af;
}

.input-error-text {
  margin-top: 6px;
  font-size: 13px;
  color: #ef4444;
}

.input-hint {
  margin-top: 6px;
  font-size: 12px;
  color: #9ca3af;
}

.error-banner {
  display: flex;
  align-items: start;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 12px;
  border: 1px solid rgba(239, 68, 68, 0.2);
  background: rgba(239, 68, 68, 0.05);
}

.dark .error-banner {
  border-color: rgba(239, 68, 68, 0.3);
  background: rgba(239, 68, 68, 0.1);
}

/* ============ SUBMIT BUTTON ============ */
.submit-btn {
  position: relative;
  width: 100%;
  height: 50px;
  border-radius: 25px;
  border: 1.5px solid #134e4a;
  background: #134e4a;
  color: #fff;
  font-size: 15px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  overflow: hidden;
  transition: all 0.3s;
}

.dark .submit-btn {
  border-color: #14b8a6;
  background: #14b8a6;
  color: #042f2e;
}

.submit-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.submit-btn .btn-text {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s;
}

.submit-btn .btn-hover-content {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  background: #14b8a6;
  color: #fff;
  opacity: 0;
  transition: all 0.3s;
  border-radius: 25px;
}

.dark .submit-btn .btn-hover-content {
  background: #0d9488;
  color: #fff;
}

.submit-btn:not(:disabled):hover .btn-text {
  transform: translateX(40px);
  opacity: 0;
}

.submit-btn:not(:disabled):hover .btn-hover-content {
  opacity: 1;
}

/* ============ ANIMATED CHARACTERS ============ */
.characters-scene {
  position: relative;
  width: 480px;
  height: 360px;
}

.character {
  position: absolute;
  bottom: 0;
  transition: all 0.7s ease-in-out;
  transform-origin: bottom center;
}

.char-primary {
  left: 60px;
  width: 170px;
  height: 370px;
  background: #14b8a6;
  border-radius: 10px 10px 0 0;
  z-index: 1;
}

.dark .char-primary {
  background: #0d9488;
}

.char-dark {
  left: 220px;
  width: 115px;
  height: 290px;
  background: #334155;
  border-radius: 8px 8px 0 0;
  z-index: 2;
}

.dark .char-dark {
  background: #1e293b;
}

.char-orange {
  left: 0;
  width: 230px;
  height: 190px;
  background: #fb923c;
  border-radius: 115px 115px 0 0;
  z-index: 3;
}

.char-yellow {
  left: 290px;
  width: 135px;
  height: 215px;
  background: #facc15;
  border-radius: 68px 68px 0 0;
  z-index: 4;
}

.eyes {
  position: absolute;
  display: flex;
  transition: all 0.7s ease-in-out;
}

.eyeball {
  border-radius: 50%;
  background: white;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: height 0.15s ease;
  overflow: hidden;
}

.pupil {
  border-radius: 50%;
  background: #1e293b;
  transition: transform 0.1s ease-out;
}

.bare-pupil {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #1e293b;
  transition: transform 0.7s ease-in-out;
}

.yellow-mouth {
  position: absolute;
  width: 50px;
  height: 4px;
  background: #1e293b;
  border-radius: 2px;
  transition: all 0.7s ease-in-out;
}

.orange-mouth {
  position: absolute;
  width: 28px;
  height: 14px;
  border: 3px solid #1e293b;
  border-top: none;
  border-radius: 0 0 14px 14px;
  opacity: 0;
  transition: all 0.7s ease-in-out;
}

.orange-mouth.visible {
  opacity: 1;
}

@keyframes shakeHead {
  0%, 100% { translate: 0 0; }
  10%  { translate: -9px 0; }
  20%  { translate: 7px 0; }
  30%  { translate: -6px 0; }
  40%  { translate: 5px 0; }
  50%  { translate: -4px 0; }
  60%  { translate: 3px 0; }
  70%  { translate: -2px 0; }
  80%  { translate: 1px 0; }
  90%  { translate: -0.5px 0; }
}

.eyes.shake-head,
.yellow-mouth.shake-head,
.orange-mouth.shake-head {
  animation: shakeHead 0.8s cubic-bezier(0.36, 0.07, 0.19, 0.97) both;
}

/* ============ TRANSITIONS ============ */
.fade-enter-active,
.fade-leave-active {
  transition: all 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

/* ============ REDUCED MOTION ============ */
@media (prefers-reduced-motion: reduce) {
  .character,
  .eyes,
  .eyeball,
  .pupil,
  .bare-pupil,
  .yellow-mouth,
  .orange-mouth {
    transition: none !important;
  }

  .eyes.shake-head,
  .yellow-mouth.shake-head,
  .orange-mouth.shake-head {
    animation: none !important;
  }
}
</style>
