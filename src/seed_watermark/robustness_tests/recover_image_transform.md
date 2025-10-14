# Recover rotation, mirroring, crop, and scale between two images

You’re given an **original** image \(I\) and a **modified** image \(J\), where \(J\) was produced from \(I\) by some combination of **rotation**, **mirroring**, and **crop+scale**.  
Below is a compact, robust, and fast scheme to estimate all operations.

---

## Overview of the pipeline

1. **Coarse rotation & scale (plus mirror) via Fourier–Mellin**
   - Use FFT **magnitudes**, convert to **log–polar**, align with **phase correlation**.
   - Test **no-mirror** vs **mirror** hypotheses; pick the one with the stronger peak.
2. **Undo the found similarity** on \(J\) (mirror/rotate/scale back).
3. **Translation & crop** via **spatial phase correlation** between \(I\) and the rectified \(J\).
4. (Optional) **Refine** all parameters with a small Gauss–Newton step (e.g., ECC alignment) or a **feature+RANSAC** similarity.

This is \(O(N\log N)\) (dominated by FFTs), works well for large images, and is resilient to moderate crops.

---

## Notation

- Forward similarity transform (original \(\to\) modified):
  \[
  y = T(x) = s\, R(\theta)\, x + t,\quad R(\theta)=
  \begin{bmatrix}\cos\theta & -\sin\theta\\ \sin\theta & \cos\theta\end{bmatrix},
  \]
  optionally composed with a **horizontal mirror** \(M=\operatorname{diag}(-1,1)\) in either input or output frame.  
- We’ll estimate \(\hat s, \hat\theta, \widehat{\text{mirror}}, \hat t\) and the **crop rectangle** in \(I\)’s coordinates.

---

## Stage 1 — Rotation & scale (and mirror) with Fourier–Mellin

### Why it works (intuition)
- Spatial **translation** only affects the **phase** of the Fourier transform; the **magnitude** \(|\mathcal F\{\cdot\}|\) is translation-invariant.
- **Rotation** of the image rotates its magnitude spectrum by the same angle.
- **Uniform scale** in space scales **radial frequency**; in **log–polar** coordinates \((\rho,\theta)\) with \(\rho=\log r\), this becomes a **translation**.

### Steps
1. **Preprocess**  
   Convert to grayscale, apply a Hanning window (or light high-pass), and (optionally) downsample.
2. **FFT magnitudes**  
   \[
   A=\big|\mathcal F\{I\}\big|,\qquad B=\big|\mathcal F\{J\}\big|.
   \]
3. **Log–polar remap**  
   \[
   \tilde A = \operatorname{LogPolar}(A),\quad \tilde B=\operatorname{LogPolar}(B).
   \]
   Use radii \(r\in[r_{\min},r_{\max}]\) (ignore the DC neighborhood), and \(\theta\in[-\pi,\pi)\).
4. **Phase correlation in log–polar**
   - Compute the **cross power spectrum**
     \[
     R = \frac{\mathcal F\{\tilde A\}\;\overline{\mathcal F\{\tilde B\}}}{\big|\mathcal F\{\tilde A\}\;\overline{\mathcal F\{\tilde B\}}\big|},
     \]
     then inverse FFT to get a correlation surface; the **peak** at \((\Delta\theta,\Delta\rho)\) gives:
     \[
     \hat\theta=\Delta\theta,\qquad \hat s = e^{\Delta\rho}.
     \]
5. **Mirror disambiguation (cheap two-hypothesis test)**
   - Because magnitudes are even, a mirror can’t be decided from \(|\cdot|\) alone. Run step 4 **twice**:
     - H0: no flip.
     - H1: horizontally flip \(J\) (or flip \(\tilde B\) along \(\theta\)).
   - Keep the hypothesis with the **higher peak value** (or—more robust—higher inlier count in the refinement step below).

> **Output of Stage 1:** \(\hat s, \hat\theta,\ \widehat{\text{mirror}}\).

---

## Stage 2 — Undo the similarity on \(J\)

Apply the **inverse** of the estimated similarity to \(J\):

1. If mirrored, flip \(J\) horizontally.
2. Rotate by \(-\hat\theta\).
3. Scale by \(1/\hat s\).

Call the result \(J_{\text{rect}}\). It lives on \(J\)’s canvas; beyond-coverage pixels can be filled with 0 or a mask.

---

## Stage 3 — Translation & crop via spatial phase correlation

With rotation/scale normalized, \(J_{\text{rect}}\) should match a **translated subregion** of \(I\).

1. **Phase correlation (spatial)**
   - Compute phase correlation between \(I\) and \(J_{\text{rect}}\) (use Hanning windows and, if available, masks to ignore padded areas in \(J_{\text{rect}}\)).
   - The correlation **peak** gives translation \((\hat t_x,\hat t_y)\) that **places** \(J_{\text{rect}}\) inside \(I\):
     \[
     I(x) \approx J_{\text{rect}}(x - \hat t).
     \]
   - Subpixel refine by fitting a paraboloid to the \(3\times3\) neighborhood around the peak.
2. **Crop rectangle in \(I\)’s frame**
   - Let \(W_J \times H_J\) be the size of the **original** \(J\). After inverse-warping, \(J_{\text{rect}}\) spans \([0,W_J)\times[0,H_J)\) in its own grid.  
   - Map its four corners into \(I\) by just **translating** with \(\hat t\):
     \[
     c_k^{(I)} = \hat t + c_k^{(J_{\text{rect}})},\quad c_k\in\{(0,0),(W_J,0),(0,H_J),(W_J,H_J)\}.
     \]
   - Intersect the resulting rectangle with \(I\)’s bounds \([0,W_I)\times[0,H_I)\) to get the **crop box** (top-left, width, height) in \(I\).

> **Outputs so far:** translation \(\hat t\) (in \(I\) pixels) and the **crop rectangle** in \(I\).

---

## Optional refinement (improves accuracy, resolves tight crops)

- **ECC alignment (Gauss–Newton):** maximize enhanced correlation coefficient between \(I\) and \(J\) under a **similarity** warp \((s,\theta,t)\). Initialize with \((\hat s,\hat\theta,\hat t)\); 5–10 iterations suffice.
- **Feature fallback (robust to tiny overlaps):**
  1. Detect ORB/SIFT in \(I\) and, for **two hypotheses** (no flip / flipped) in \(J\).
  2. Match descriptors \(\to\) run RANSAC with a **similarity** model:
     \[
     y_i \approx s\,R(\theta)\,x_i + t.
     \]
     Estimate with **Umeyama** (SVD) on inliers.
  3. Choose the hypothesis with more inliers / lower reprojection error.  
  This often succeeds when frequency methods degrade due to very small crops or heavy apodization.

---

## Practical details & parameters

- **Windows:** Hanning/Hamming windows before FFT and before spatial correlation reduce edge artifacts and sharpen the peak.
- **Log–polar grid:** \(N_\theta \in [180,360]\), \(N_\rho \in [128,256]\). Exclude a small radius around DC (e.g., \(r<5\) px in frequency).
- **Pre-whitening:** Use gradient magnitude or apply a mild high-pass to reduce bias from illumination changes.
- **Mirror direction:** A vertical flip equals a horizontal flip plus \(180^\circ\) rotation; testing **horizontal only** is sufficient.
- **Robust peak selection:** Use peak **height / sidelobe ratio** and refine subpixelly; reject if too flat.
- **Masks for crops:** If you have a confidence mask of valid pixels in \(J_{\text{rect}}\), use **masked phase correlation** to ignore padded/background areas.
- **Complexity:** Each FFT is \(O(N\log N)\); total cost is a handful of FFTs at reduced resolutions.

---

## What you recover (summary)

- **Mirroring:** present/absent (and direction, by convention horizontal).
- **Rotation:** \(\hat\theta\) (degrees or radians).
- **Scale:** \(\hat s\) (relative to \(I\)).
- **Translation:** \(\hat t=(\hat t_x,\hat t_y)\) in \(I\)-pixel units (after undoing \(\hat s,\hat\theta\)).
- **Crop box:** rectangle in \(I\) that maps to \(J\) after applying the forward similarity.

---

## Minimal algorithmic sketch (language-agnostic)

```text
INPUT: Original image I, modified image J.

(1) Preprocess: grayscale, window; compute FFT magnitudes A=|FFT(I)|, B=|FFT(J)|.
(2) Log–polar remap: LA = LogPolar(A), LB = LogPolar(B).

(3) Rotation/scale (no-flip):    (dθ0, dρ0, p0) = PhaseCorrelate(LA, LB)
(4) Rotation/scale (h-flipped):  (dθ1, dρ1, p1) = PhaseCorrelate(LA, FlipH(LB))

(5) If p1 > p0: mirror = True;  (θ, s) = (dθ1, exp(dρ1))
    else:       mirror = False; (θ, s) = (dθ0, exp(dρ0))

(6) Rectify J: Jrect = Undo(mirror, θ, s) on J.

(7) Translation: (tx, ty) = PhaseCorrelate(I, Jrect)  # (use windows/masks)

(8) Crop box in I:
    top_left = (tx, ty)
    size     = (width(J), height(J))    # in Jrect coordinates
    crop_box = IntersectWithBounds( top_left, size, bounds(I) )

OUTPUT: mirror, θ, s, translation (tx, ty), crop_box.
```

---

## Notes on correctness and edge cases

- **Why crop doesn’t break Stage 1 completely:** cropping in space multiplies by a window; in frequency it convolves spectra, which blurs—but does not destroy—the rotation/scale structure. With enough shared content, the log–polar peak remains detectable.
- **Very small overlap / heavy blur:** go straight to the **feature+RANSAC** fallback.
- **Non-uniform scaling or slight projective warp:** refine with an **affine** model in the feature step; for mild deviations, similarity is usually enough.
