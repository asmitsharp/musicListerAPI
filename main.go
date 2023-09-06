package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Playlists  []Playlist
	SecretCode string `json:"secretCode"`
}

type Playlist struct {
	ID    string `json:"playId"`
	Name  string `json:"name"`
	Songs []Song
}

type Song struct {
	ID      string `json:"songId"`
	Title   string `json:"title"`
	Singer  string `json:"singer"`
	SongURL string `json:"songURL"`
}

var (
	users      []User
	playlists  []Playlist
	tokens     map[string]string
	idCounter  int
	nextUserId = 1
	mu         sync.Mutex
)

func generateUniqueID() string {
	timestamp := time.Now().UnixNano()

	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "fallbackID"
	}
	randomNumber := int64(binary.BigEndian.Uint64(randomBytes))

	uniqueID := timestamp + randomNumber
	idCounter++
	finalId := strconv.FormatInt(uniqueID, 16)

	return finalId
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Inalid data", http.StatusBadRequest)
		return
	}

	var foundUser User
	for _, user := range users {
		if user.Username == requestBody["username"] {
			foundUser = user
			break
		}
	}

	if foundUser.Username != "" && foundUser.SecretCode == requestBody["seceretCode"] {
		token := generateUniqueID()
		tokens[token] = foundUser.Username

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	} else {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var newUser User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	for _, user := range users {
		if user.Username == newUser.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	mu.Lock()
	defer mu.Unlock()

	newUser.ID = nextUserId
	users = append(users, newUser)
	nextUserId++

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newUser)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		if username, ok := tokens[token]; ok {
			r = r.WithContext(context.WithValue(r.Context(), "username", username))
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	}
}

func viewProfileHandler(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for _, user := range users {
		if user.ID == userId {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(user.Playlists)
			return
		}
	}

	http.Error(w, "User not found", http.StatusNotFound)
}

func createPlaylistHandler(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var newPlaylist Playlist
	if err := json.NewDecoder(r.Body).Decode(&newPlaylist); err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}

	newPlaylist.ID = generateUniqueID()

	mu.Lock()
	defer mu.Unlock()

	for i, user := range users {
		if user.ID == userId {
			users[i].Playlists = append(users[i].Playlists, newPlaylist)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(newPlaylist)
			return
		}
	}
	http.Error(w, "User not found", http.StatusNotFound)
}

func addSongHandler(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	playlistId := r.URL.Query().Get("playId")

	var newSong Song
	if err := json.NewDecoder(r.Body).Decode(&newSong); err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for i, user := range users {
		if user.ID == userId {
			for j, playlist := range user.Playlists {
				if playlist.ID == playlistId {
					newSong.ID = generateUniqueID()
					users[i].Playlists[j].Songs = append(users[i].Playlists[j].Songs, newSong)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(newSong)
					return
				}
			}
		}
	}
}

func deleteSongPlaylistHandler(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	playlistId := r.URL.Query().Get("playId")
	songID := r.URL.Query().Get("songId")

	mu.Lock()
	defer mu.Unlock()

	for i, user := range users {
		if user.ID == userId {
			for j, playlist := range user.Playlists {
				if playlist.ID == playlistId {
					for k, song := range playlist.Songs {
						if song.ID == songID {
							users[i].Playlists[j].Songs = append(playlist.Songs[:k], playlist.Songs[k+1:]...)
							for l, globalSong := range playlists {
								if globalSong.ID == songID {
									playlists = append(playlists[:l], playlists[l+1:]...)
									break
								}
							}

							w.WriteHeader(http.StatusNoContent)
							return
						}
					}
				}
			}
		}
	}
}

func deletePlaylistHandler(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	playlistId := r.URL.Query().Get("playId")

	mu.Lock()
	defer mu.Unlock()

	for i, user := range users {
		if user.ID == userId {
			for j, playlist := range user.Playlists {
				if playlist.ID == playlistId {
					users[i].Playlists = append(users[i].Playlists[:j], users[i].Playlists[j+1:]...)
					for k, globalPlaylist := range playlists {
						if globalPlaylist.ID == playlistId {
							playlists = append(playlists[:k], playlists[k+1:]...)
							break
						}
					}

					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
	}
}

func getPlaylistSongHandler(w http.ResponseWriter, r *http.Request) {
	songID := r.URL.Query().Get("songId")

	mu.Lock()
	defer mu.Unlock()

	for _, song := range playlists {
		if song.ID == songID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(song)
			return
		}
	}

	http.Error(w, "Song not found", http.StatusNotFound)
}

func main() {

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)

	// Protected routes
	http.HandleFunc("/viewProfile", authMiddleware(viewProfileHandler))
	http.HandleFunc("/createPlaylist", authMiddleware(createPlaylistHandler))
	http.HandleFunc("/addSong", authMiddleware(addSongHandler))
	http.HandleFunc("/deleteSongPlaylist", authMiddleware(deleteSongPlaylistHandler))
	http.HandleFunc("/getPlaylistSong", authMiddleware(getPlaylistSongHandler))
	http.HandleFunc("deletePlaylist", authMiddleware(deletePlaylistHandler))

	fmt.Println("Server is running on :3000")
	http.ListenAndServe(":3000", nil)
}
